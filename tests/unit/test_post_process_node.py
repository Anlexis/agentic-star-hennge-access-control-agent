# Unit tests: PostProcessNode - the output boundary.
#
# Canon: invoked via node(state), so the framework's full security pipeline runs
# (trust gate -> input gate -> execute() -> output gate); this backbone
# formatter declares ANONYMOUS -> the state builder sets
# caller_trust_level = TrustLevel.ANONYMOUS.value. The domain output gate is the
# MODULE-LEVEL _security_gate_output() helper (the framework gate methods are
# @final and the SDK auto-wraps _extra_ hooks), so the helper is also unit-tested
# directly as a plain function.
#
# The already-errored branch is driven through execute(): BaseNode.__call__
# short-circuits on an incoming errored state, and the backbone routes an error
# straight to finalize, so that branch is only reachable from inside.

import json

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.post_process_node import (
    ERROR_REASONS,
    PostProcessNode,
    _OUTPUT_BEARING_FIELDS,
    _REASON_OUTPUT_WITHHELD,
    _REASON_WORKFLOW_FAILED,
    _security_gate_output,
)
from src.schemas.state import to_json


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    monkeypatch.setattr("src.nodes.post_process_node.emit_trace_event", lambda *a, **k: None)


def _state(**overrides) -> dict:
    state = {
        "status": AgentStatus.SUCCESS.value,
        "record_id": "u-1001",
        "record_ref": "hennge://users/u-1001/applications",
        "user_id": "u-1001",
        "app_name": "Salesforce",
        "intent": "lookup_access",
        "confirmation": "Retrieved app access status 'Salesforce' - user=u-1001 - id=u-1001",
        "hennge_payload": to_json({"user_id": "u-1001"}),
        "caller_trust_level": TrustLevel.ANONYMOUS.value,
        "correlation_id": "post-process-test",
        "node_history": [],
        "error_log": [],
        "execution_time": {},
    }
    state.update(overrides)
    return state


def _bearer() -> str:
    # Built at runtime so no credential-shaped literal is committed.
    return "Bearer " + "a" * 24


def _sentinel() -> str:
    """An error_log line of the kind an upstream failure produces: a name and a
    credential-shaped token inside an echoed response body. Assembled at runtime
    so no credential-shaped literal is committed."""
    token = "sk-" + "live-" + "x" * 3
    return "boom: upstream said {'customer':'A. Tanaka','token':'" + token + "'}"


_SENTINEL_FRAGMENTS = ("A. Tanaka", "boom: upstream", "sk-" + "live-")


def _strings_in(value):
    """Every string reachable in a nested structure - mapping keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings_in(key)
            yield from _strings_in(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings_in(item)
    elif value is not None and not isinstance(value, (bool, int, float)):
        yield str(value)


def _payload_with_nested_credential() -> str:
    return to_json({"access_request": [{"attributes": [{"values": [_bearer()]}]}]})


def _run(node: PostProcessNode, state: dict) -> dict:
    """Drive post_process the way the pipeline can: execute() for an errored
    state (BaseNode.__call__ short-circuits on it), node(state) otherwise."""
    if state.get("status") == AgentStatus.ERROR.value:
        return node.execute(state)
    return node(state)


class TestPostProcessNode:
    def setup_method(self):
        self.node = PostProcessNode()

    def test_success_formats_output(self):
        result = self.node(_state())
        assert result["status"] == AgentStatus.SUCCESS.value
        out = result["formatted_output"]
        assert out["record_id"] == "u-1001"
        assert out["record_ref"] == "hennge://users/u-1001/applications"
        assert out["user_id"] == "u-1001"
        assert out["app_name"] == "Salesforce"
        assert out["intent"] == "lookup_access"
        assert out["confirmation"].startswith("Retrieved app access status")
        # Round-trip: the JSON hennge_payload string surfaces parsed.
        assert out["hennge_payload"] == {"user_id": "u-1001"}

    def test_status_is_plain_string_not_enum(self):
        """State status must be the `.value` string, never a bare AgentStatus
        member - str-enum equality masks the difference in `==` asserts, so pin
        the concrete type here."""
        result = self.node(_state())
        assert isinstance(result["status"], str)
        assert not isinstance(result["status"], AgentStatus)
        assert result["status"] == AgentStatus.SUCCESS.value

    def test_error_status_preserved(self):
        """Inner-workflow error must not be masked as success. Real pipeline
        behaviour: BaseNode.__call__ short-circuits on an incoming errored state
        (execute() is skipped), so the error status + error_log pass through
        untouched and no success shape is fabricated."""
        state = _state(
            status=AgentStatus.ERROR.value,
            record_id="",
            record_ref="",
            error_log=["CallHenngeApiNode: HENNGE API error 403"],
        )
        result = self.node(state)
        assert result["status"] == AgentStatus.ERROR.value
        assert "HENNGE API error 403" in "\n".join(result["error_log"])
        assert "formatted_output" not in result

    def test_error_status_as_string_value_preserved(self):
        """The framework may carry status as the enum .value (string) at the boundary."""
        result = self.node(_state(status=AgentStatus.ERROR.value, error_log=["boom"]))
        assert result["status"] == AgentStatus.ERROR.value
        assert "formatted_output" not in result

    def test_gate_blocks_success_without_record_evidence(self):
        """A SUCCESS output missing record_id/record_ref is blocked (full node path)."""
        result = self.node(_state(record_id="", record_ref=""))
        assert result["status"] == AgentStatus.ERROR.value
        assert any("output gate" in entry for entry in result["error_log"])


class TestBlockedOutputIsCleared:
    """A refusal must contain the response, not merely label it.

    The framework assembles the caller-facing envelope as
    `formatted_output or result`, and that fallback does not consult the status
    - so a gate that returns ERROR while leaving `result` in place ships the
    un-checked answer inside the error envelope.
    """

    def setup_method(self):
        self.node = PostProcessNode()

    def test_every_output_bearing_field_is_cleared(self):
        state = _state(record_id="", record_ref="")
        state["result"] = {"confirmation": "Granted app access 'Salesforce'", "record_id": "g-77"}
        result = self.node(state)

        assert result["status"] == AgentStatus.ERROR.value
        for field in _OUTPUT_BEARING_FIELDS:
            if field == "formatted_output":
                continue  # asserted below - it is REPLACED, not blanked
            assert result[field] == "", field

    def test_the_replacement_envelope_is_truthy_and_record_free(self):
        """Clearing formatted_output to a falsy value would re-open the very
        `formatted_output or result` fallback the containment exists to close
        (AgentBaseGraph.get_output() applies no status check). The refusal
        therefore REPLACES it with a truthy notice carrying a closed-set reason
        code and nothing else."""
        state = _state(record_id="", record_ref="")
        state["result"] = {"confirmation": "Granted app access 'Salesforce'", "record_id": "g-77"}
        out = self.node(state)["formatted_output"]

        assert out, "the withheld notice must be TRUTHY"
        assert out == {"reason": _REASON_OUTPUT_WITHHELD}
        rendered = repr(out)
        assert "u-1001" not in rendered
        assert "Salesforce" not in rendered
        assert "hennge://" not in rendered

    def test_no_released_text_survives_the_refusal(self):
        state = _state(record_id="", record_ref="")
        state["result"] = {"confirmation": "Granted app access 'Salesforce' - user=u-1001"}
        result = self.node(state)
        rendered = repr({k: v for k, v in result.items() if k != "error_log"})
        assert "Granted app access" not in rendered
        assert "Salesforce" not in rendered


# Every non-success path, each with the sentinel seeded into the INCOMING
# error_log so the walk below has something to find. Factories, not shared
# dicts: every test gets a fresh state.
_NON_SUCCESS_STATES = [
    pytest.param(lambda: _state(status=AgentStatus.ERROR.value, error_log=[_sentinel()]), id="inner-workflow-error"),
    pytest.param(
        lambda: _state(
            status=AgentStatus.ERROR.value,
            error_log=[_sentinel()],
            result={"confirmation": "Granted app access 'Salesforce'", "record_id": "g-77"},
        ),
        id="inner-error-with-answer-in-result",
    ),
    pytest.param(
        lambda: _state(status=AgentStatus.ERROR.value, error_log=[_sentinel(), _bearer()]),
        id="inner-error-with-credential-in-error-log",
    ),
    pytest.param(
        lambda: _state(record_id="", record_ref="", error_log=[_sentinel()]),
        id="success-without-record-evidence",
    ),
    pytest.param(
        lambda: _state(error_log=[_sentinel()], hennge_payload=_payload_with_nested_credential()),
        id="credential-nested-in-payload",
    ),
    pytest.param(
        lambda: _state(error_log=[_sentinel()], hennge_payload=to_json({"access_request": [{_bearer(): "granted"}]})),
        id="credential-shaped-mapping-key",
    ),
]


class TestErrorEnvelopeIsClosedSet:
    """On every non-success path the caller-visible envelope carries only
    values this module chose from its declared constants."""

    def setup_method(self):
        self.node = PostProcessNode()

    @pytest.mark.parametrize("make_state", _NON_SUCCESS_STATES)
    def test_every_envelope_value_is_a_declared_constant(self, make_state):
        result = _run(self.node, make_state())

        assert result["status"] == AgentStatus.ERROR.value
        out = result["formatted_output"]
        assert out, "the envelope must stay TRUTHY"
        assert set(out) == {"reason"}, out
        assert set(out.values()) <= ERROR_REASONS, out
        for field in _OUTPUT_BEARING_FIELDS:
            if field != "formatted_output":
                assert result[field] == "", field

    @pytest.mark.parametrize("make_state", _NON_SUCCESS_STATES)
    def test_sentinel_seeded_in_error_log_appears_nowhere_in_the_result(self, make_state):
        result = _run(self.node, make_state())

        found = [fragment for fragment in _SENTINEL_FRAGMENTS if any(fragment in s for s in _strings_in(result))]
        assert found == [], result

    def test_reason_code_names_the_path_taken(self):
        errored = self.node.execute(_state(status=AgentStatus.ERROR.value, error_log=[_sentinel()]))
        refused = self.node(_state(record_id="", record_ref=""))

        assert errored["formatted_output"] == {"reason": _REASON_WORKFLOW_FAILED}
        assert refused["formatted_output"] == {"reason": _REASON_OUTPUT_WITHHELD}

    def test_inner_entries_are_not_re_emitted(self):
        """error_log is accumulated by the state reducer: re-emitting the
        incoming entries would duplicate every line. The errored branch adds
        nothing to it."""
        result = self.node.execute(_state(status=AgentStatus.ERROR.value, error_log=[_sentinel()]))
        assert "error_log" not in result

    def test_gate_violations_travel_in_error_log_only(self):
        result = self.node(_state(hennge_payload=_payload_with_nested_credential()))
        reported = " ".join(result["error_log"])
        rendered = json.dumps(result["formatted_output"])

        assert "hennge_payload.access_request[0].attributes[0].values[0]" in reported
        assert _bearer() not in reported
        assert "output gate" not in rendered
        assert "hennge_payload" not in rendered

    def test_credential_shaped_key_is_withheld_from_the_label_with_the_clearing_intact(self):
        """The label rides error_log, where the framework's own credential scan
        would raise on a quoted key and replace this node's cleared result with
        a bare error - re-opening the `result` fallback. The cleared `result`
        here is the proof that the scan did not fire."""
        result = self.node(_state(hennge_payload=to_json({"access_request": [{_bearer(): "granted"}]})))
        reported = " ".join(result["error_log"])

        assert result["status"] == AgentStatus.ERROR.value
        assert result["formatted_output"] == {"reason": _REASON_OUTPUT_WITHHELD}
        assert result["result"] == ""
        assert _bearer() not in reported
        assert "<withheld>" in reported

    def test_audit_events_carry_outcome_signals_only(self, monkeypatch):
        events = []
        monkeypatch.setattr(
            "src.nodes.post_process_node.emit_trace_event",
            lambda *args, **kwargs: events.append(args),
        )
        self.node.execute(_state(status=AgentStatus.ERROR.value, error_log=[_sentinel(), "second"]))
        self.node(_state(hennge_payload=_payload_with_nested_credential()))
        payloads = {args[0]: args[1] for args in events}

        assert payloads["post_process_error_contained"] == {"reason": _REASON_WORKFLOW_FAILED, "error_count": 2}
        assert payloads["post_process_output_blocked"] == {"reason": _REASON_OUTPUT_WITHHELD, "violation_count": 1}


class TestSecurityGateOutputHelper:
    """The module-level domain output gate as a plain function (not a node call)."""

    def test_passes_success_with_record_evidence(self):
        violations = _security_gate_output(
            {"record_id": "u-1001", "record_ref": "hennge://users/u-1001/applications", "confirmation": "ok"},
            is_success=True,
        )
        assert violations == []

    def test_blocks_success_without_record_evidence(self):
        violations = _security_gate_output(
            {"record_id": "", "record_ref": "", "confirmation": "looks done"},
            is_success=True,
        )
        assert len(violations) == 1
        assert "record_id/record_ref" in violations[0]

    def test_blocks_credential_shaped_value(self):
        violations = _security_gate_output(
            {"record_id": "u-1001", "note": _bearer()},
            is_success=True,
        )
        assert any("note" in v for v in violations)

    def test_blocks_credential_nested_inside_the_payload(self):
        """Scanning only top-level strings misses the place a token actually rides."""
        violations = _security_gate_output(
            {
                "record_id": "u-1001",
                "hennge_payload": {"access_request": [{"attributes": [{"values": [_bearer()]}]}]},
            },
            is_success=True,
        )
        assert any("hennge_payload" in v for v in violations)

    def test_blocks_credential_shaped_mapping_key_and_withholds_it_from_the_label(self):
        violations = _security_gate_output(
            {"record_id": "u-1001", "hennge_payload": {_bearer(): "granted"}},
            is_success=True,
        )
        assert len(violations) == 1
        assert "hennge_payload.<withheld>" in violations[0]
        assert _bearer() not in violations[0]

    def test_clean_nested_payload_passes(self):
        """The control that proves the nested probe is not simply always-firing."""
        violations = _security_gate_output(
            {
                "record_id": "u-1001",
                "hennge_payload": {"access_request": [{"attributes": [{"values": ["read_only"]}]}]},
            },
            is_success=True,
        )
        assert violations == []

    def test_error_output_not_required_to_carry_evidence(self):
        violations = _security_gate_output({"record_id": "", "record_ref": ""}, is_success=False)
        assert violations == []
