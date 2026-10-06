# Proof of boundary: the ERROR envelope must CONTAIN the failure, not re-publish it.
#
# molt source review, 2026-09-04 (wave-9 batch), family finding across sixteen
# sibling repos. Two channels, both caller-visible:
#
#   1. the existing-ERROR branch of PostProcessNode.execute() rebuilt a truthy
#      `formatted_output` out of `record_id` / `record_ref` read straight back
#      from state, and returned a delta of ONLY formatted_output + status - so
#      every other output-bearing field survived in state;
#   2. `error_log` entries carried interpolated identifiers and upstream/
#      exception text rather than closed-set labels - and, at the time, the
#      envelope re-published error_log under `formatted_output["error"]`. The
#      envelope no longer carries error_log at all (see
#      test_output_envelope_containment.py); the entries are still held to
#      closed-set labels here because error_log is the audit channel.
#
# Why the identifiers matter here: `record_id` / `record_ref` are this agent's
# WRITE EVIDENCE - `_security_gate_output()` REFUSES a SUCCESS that lacks them.
# An envelope carrying them under an ERROR status tells a caller being told the
# operation failed that a HENNGE Access Control record was nonetheless touched,
# and which one. HENNGE One is an identity/access system: the user id, the
# application name and the access/grant references are personal data, and the
# grant/revocation ids are the audit trail of a privileged write.
#
# REACHABILITY (stated honestly, per the review): this branch is NOT reachable
# through the compiled graph. AgentBaseGraph.route() sends an ERROR status to
# `finalize`, bypassing `post_process`, and BaseNode.__call__ short-circuits an
# already-errored state before execute() runs. The tests below therefore call
# execute() DIRECTLY. This is source-level defence in depth - the branch exists,
# is exercised by the unit suite, and would ship the evidence the moment any
# future routing change or direct invocation reached it.

import json

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.call_hennge_api_node import CallHenngeApiNode
from src.nodes.post_process_node import PostProcessNode
from src.schemas.state import to_json

# The HENNGE record evidence and personal fields that must never ride an error
# envelope. Values match the state fixture below.
_USER_ID = "u-1001"
_RECORD_ID = "g-77"
_RECORD_REF = "hennge://access-grants/g-77"
_APP_NAME = "Salesforce"

# Every State field that can carry text produced by the inner workflow. The
# error delta must blank all of them - omitting a field from ONE envelope is
# not clearing it from state, where a checkpoint or a downstream reader picks
# it straight back up.
_OUTPUT_BEARING = (
    "result",
    "confirmation",
    "record_id",
    "record_ref",
    "user_id",
    "app_name",
    "intent",
    "hennge_payload",
    "redaction_flags",
)


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    monkeypatch.setattr("src.nodes.post_process_node.emit_trace_event", lambda *a, **k: None)
    monkeypatch.setattr("src.nodes.call_hennge_api_node.emit_trace_event", lambda *a, **k: None)


def _state(**overrides) -> dict:
    state = {
        "status": AgentStatus.SUCCESS.value,
        "record_id": _RECORD_ID,
        "record_ref": _RECORD_REF,
        "user_id": _USER_ID,
        "app_name": _APP_NAME,
        "intent": "grant_access",
        "confirmation": f"Granted app access '{_APP_NAME}' - user={_USER_ID} - id={_RECORD_ID}",
        "hennge_payload": to_json({"user_id": _USER_ID, "app_name": _APP_NAME}),
        "caller_trust_level": TrustLevel.ANONYMOUS.value,
        "correlation_id": "error-envelope-pob",
        "session_id": "s1",
        "thread_id": "th1",
        "trace_id": "t1",
        "node_history": [],
        "error_log": [],
        "execution_time": {},
    }
    state.update(overrides)
    return state


def _errored_state() -> dict:
    """A failure raised AFTER the HENNGE call resolved a record.

    This is the only shape in which record evidence is present on an error at
    all: the write landed, a later step failed. Anything else has nothing to
    leak, so a fixture without the evidence would make the test vacuous.
    """
    state = _state(status=AgentStatus.ERROR.value)
    state["result"] = {
        "record_id": _RECORD_ID,
        "record_ref": _RECORD_REF,
        "confirmation": f"Granted app access '{_APP_NAME}' - user={_USER_ID}",
    }
    state["error_log"] = ["ConfirmNode: downstream failure after the HENNGE call"]
    return state


class TestErrorEnvelopeCarriesNoRecordEvidence:
    """Channel 1: the caller-facing envelope and the state it leaves behind."""

    def test_envelope_is_present_and_truthy(self):
        """Containment must NOT be achieved by emptying the envelope.

        AgentBaseGraph.get_output() projects `formatted_output or result` with
        no status check, so a falsy formatted_output hands the caller whatever
        `result` holds - the exact fallback this containment exists to close.
        """
        result = PostProcessNode().execute(_errored_state())
        assert "formatted_output" in result, "the error path must still ship an envelope"
        assert result["formatted_output"], (
            "error envelope must be TRUTHY - a falsy one re-opens the "
            "`formatted_output or result` fallback in AgentBaseGraph.get_output()"
        )

    def test_envelope_names_no_record(self):
        """The leak itself: no identifier or personal field may ride the failure."""
        shipped = json.dumps(
            PostProcessNode().execute(_errored_state())["formatted_output"],
            default=str,
            ensure_ascii=False,
        )
        leaked = [
            field
            for field, value in (
                ("record_id", _RECORD_ID),
                ("record_ref", _RECORD_REF),
                ("user_id", _USER_ID),
                ("app_name", _APP_NAME),
            )
            if value in shipped
        ]
        assert not leaked, f"error envelope leaked HENNGE record evidence: {leaked} in {shipped}"

    def test_error_delta_clears_output_bearing_state(self):
        """ "Retains output-bearing state": the delta must blank every field."""
        result = PostProcessNode().execute(_errored_state())
        retained = [field for field in _OUTPUT_BEARING if field not in result or result[field]]
        assert not retained, (
            f"output-bearing state not cleared on the error path: {retained}; " f"delta keys = {sorted(result)}"
        )

    def test_error_status_is_still_reported(self):
        """Containment must not mask the failure."""
        assert PostProcessNode().execute(_errored_state())["status"] == AgentStatus.ERROR.value

    def test_clean_path_control_still_returns_the_evidence(self):
        """CONTROL. Without it every assertion above passes vacuously - a node
        that returned an empty envelope and cleared everything would satisfy
        them all. The success path must still carry the record evidence."""
        result = PostProcessNode().execute(_state())
        assert result["status"] == AgentStatus.SUCCESS.value
        out = result["formatted_output"]
        assert out["record_id"] == _RECORD_ID
        assert out["record_ref"] == _RECORD_REF
        assert out["user_id"] == _USER_ID
        assert out["app_name"] == _APP_NAME
        assert out["confirmation"].startswith("Granted app access")
        assert out["hennge_payload"] == {"user_id": _USER_ID, "app_name": _APP_NAME}


class TestErrorReasonsAreClosedSetLabels:
    """Channel 2: the reasons written to `error_log`.

    The caller-visible envelope no longer carries error_log, but the log is
    the audit channel, and a reason that interpolates the user id records the
    account by another key; an upstream error body is unbounded third-party
    text that can quote the very account it refused. Only closed-set labels -
    the intent, the HTTP status, the exception TYPE - may travel.
    """

    _CONFIG = {"configurable": {"hennge": {"base_url": "https://api.hennge.test/v1"}}}

    def _call_state(self, **overrides) -> dict:
        state = _state(
            status=AgentStatus.PENDING.value,
            record_id="",
            record_ref="",
            confirmation="",
        )
        state.update(overrides)
        return state

    def test_empty_lookup_reason_does_not_name_the_user(self):
        class _Client:
            uses_stub_transport = True

            def get_user_access(self, user_id, api_token):
                return {"access_data": []}

        node = CallHenngeApiNode()
        state = self._call_state(intent="lookup_access")
        result = self._run(node, state, _Client())
        reasons = "\n".join(result["error_log"])
        assert _USER_ID not in reasons, f"empty-lookup reason named the account: {reasons!r}"

    def test_empty_policy_reason_does_not_name_the_user(self):
        class _Client:
            uses_stub_transport = True

            def get_user_policies(self, user_id, api_token):
                return {"policy_data": []}

        node = CallHenngeApiNode()
        state = self._call_state(intent="check_policy")
        result = self._run(node, state, _Client())
        reasons = "\n".join(result["error_log"])
        assert _USER_ID not in reasons, f"empty-policy reason named the account: {reasons!r}"

    def test_api_error_reason_does_not_carry_the_upstream_body(self):
        """A live tenant's error body can echo the account it refused."""
        from src.services.hennge_client import HenngeApiError

        body = f"denied for {_USER_ID} on {_APP_NAME} (contact admin@acme.example)"

        class _Client:
            uses_stub_transport = True

            def grant_access(self, payload, api_token):
                raise HenngeApiError(403, body)

        node = CallHenngeApiNode()
        state = self._call_state(intent="grant_access")
        result = self._run(node, state, _Client())
        reasons = "\n".join(result["error_log"])
        assert "403" in reasons, "the closed-set signal (HTTP status) must still travel"
        assert body not in reasons, f"reason carried the upstream body verbatim: {reasons!r}"
        assert _USER_ID not in reasons, f"reason named the account: {reasons!r}"
        assert _APP_NAME not in reasons, f"reason named the application: {reasons!r}"

    def test_transport_failure_reason_carries_the_type_not_the_string(self):
        detail = f"HTTPSConnectionPool(host='api.hennge.test'): /users/{_USER_ID}/applications"

        class _Client:
            uses_stub_transport = True

            def revoke_access(self, payload, api_token):
                raise ConnectionError(detail)

        node = CallHenngeApiNode()
        state = self._call_state(intent="revoke_access")
        result = self._run(node, state, _Client())
        reasons = "\n".join(result["error_log"])
        assert "ConnectionError" in reasons, "the closed-set signal (exception type) must travel"
        assert _USER_ID not in reasons, f"transport reason named the account: {reasons!r}"

    def test_control_successful_call_still_returns_the_evidence(self):
        """CONTROL for this class: a reason-sanitising change must not turn the
        clean call into an error."""

        class _Client:
            uses_stub_transport = True

            def grant_access(self, payload, api_token):
                return {"grant_id": _RECORD_ID}

        node = CallHenngeApiNode()
        state = self._call_state(intent="grant_access")
        result = self._run(node, state, _Client())
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["record_id"] == _RECORD_ID

    @staticmethod
    def _run(node, state, client) -> dict:
        import src.nodes.call_hennge_api_node as mod

        original = mod.HenngeClient
        mod.HenngeClient = lambda *a, **k: client
        try:
            return node.execute(state, config=TestErrorReasonsAreClosedSetLabels._CONFIG)
        finally:
            mod.HenngeClient = original
