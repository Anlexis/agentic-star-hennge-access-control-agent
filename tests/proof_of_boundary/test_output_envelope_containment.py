# Proof of boundary (containment): what the caller receives on every
# non-success path - through the agent's own envelope projection, and through
# the real ASGI /invoke entry point.
#
# The framework assembles the caller envelope as `formatted_output or result`
# and never looks at the status; by the time post_process runs, `result`
# already holds the inner workflow's answer. So an error return that merely
# sets the status, or that replaces formatted_output with something falsy,
# ships the answer it refused inside an envelope that calls itself an error.
# And an envelope that carries error_log ships every node-authored line: an
# upstream API error body, identifiers, names - text that no truncation, path
# stripping or credential-only redaction turns into a closed set.
#
# Two layers, both exercised with the same sentinel seeded into error_log:
#
#   1. post_process driven over its real call path where the framework
#      pipeline allows (node(state): trust gate, input gate, execute,
#      credential scan), and through execute() for an already-errored state
#      (BaseNode.__call__ short-circuits on it and the backbone routes an
#      error straight to finalize, so that branch is only reachable from
#      inside). The returned partial state is merged the way the state
#      reducer merges it and projected through the agent's get_output() -
#      exactly what the caller reads.
#   2. the real ASGI /invoke: the sentinel is seeded by an inner node and a
#      spy on the boundary node proves it arrived there; the HTTP body is then
#      walked - nested keys and values - and the sentinel must be nowhere.
#
# The clean-path controls are deliberate: they fail if the gate ever starts
# refusing everything, so containment cannot be "achieved" by returning
# nothing at all.

import json
import os
import re
import warnings
from collections.abc import Iterator

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import HENNGEAccessControlAgent
from src.nodes.call_hennge_api_node import CallHenngeApiNode
from src.nodes.confirm_node import ConfirmNode
from src.nodes.post_process_node import (
    ERROR_REASONS,
    _REASON_OUTPUT_WITHHELD,
    _REASON_WORKFLOW_FAILED,
    PostProcessNode,
)
from src.schemas.state import to_json

_USER_ID = "u-1001"
_RECORD_ID = "g-77"
_RECORD_REF = "hennge://access-grants/g-77"
_APP_NAME = "Salesforce"
_CONFIRMATION = f"Granted app access '{_APP_NAME}' - user={_USER_ID} - ref={_RECORD_REF} - id={_RECORD_ID}"

# Fields the state reducer accumulates rather than replaces.
_ACCUMULATED = ("error_log", "node_history")


def _bearer() -> str:
    # Built at runtime so no credential-shaped literal is committed.
    return "Bearer " + "a" * 24


def _sentinel() -> str:
    """An error_log line of the kind an upstream failure produces: a name and a
    credential-shaped token inside an echoed response body.

    Assembled at runtime so no credential-shaped literal is committed. The
    token is shaped so that neither the domain gate nor the framework's own
    credential scan fires on it: the seed has to reach the boundary intact, or
    the walk below proves nothing. The credential-shaped probes use _bearer().
    """
    token = "sk-" + "live-" + "x" * 3
    return "boom: upstream said {'customer':'A. Tanaka','token':'" + token + "'}"


_SENTINEL_FRAGMENTS = ("A. Tanaka", "boom: upstream", "sk-" + "live-")


def _strings_in(value: object) -> Iterator[str]:
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


def _fragments_found(value: object) -> list[str]:
    return [fragment for fragment in _SENTINEL_FRAGMENTS if any(fragment in text for text in _strings_in(value))]


# ---------------------------------------------------------------------------
# Layer 1: post_process -> state reducer -> the agent's get_output()
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    monkeypatch.setattr("src.nodes.post_process_node.emit_trace_event", lambda *a, **k: None)


def _state_after_a_successful_inner_run(**overrides) -> dict:
    """The outer state as it stands when post_process runs after a clean inner
    workflow: the answer is already merged into `result` and every domain
    field is populated."""
    state = {
        "status": AgentStatus.SUCCESS.value,
        "result": {"record_id": _RECORD_ID, "record_ref": _RECORD_REF, "confirmation": _CONFIRMATION},
        "record_id": _RECORD_ID,
        "record_ref": _RECORD_REF,
        "user_id": _USER_ID,
        "app_name": _APP_NAME,
        "intent": "grant_access",
        "confirmation": _CONFIRMATION,
        "hennge_payload": to_json({"access_request": [{"user_id": _USER_ID, "app_name": _APP_NAME}]}),
        "redaction_flags": to_json([]),
        "caller_trust_level": TrustLevel.ANONYMOUS.value,
        "correlation_id": "pb-envelope",
        "trace_id": "pb-envelope-trace",
        "node_history": ["InitializeNode", "PreProcessNode", "HenngeWorkflowGraphNode"],
        "error_log": [],
        "execution_time": {},
    }
    state.update(overrides)
    return state


def _state_after_a_failed_inner_run(**overrides) -> dict:
    """The outer state when the inner workflow reported an error after the
    HENNGE call had resolved a record: the answer is still merged into
    `result`, and error_log carries the upstream failure text."""
    fields = {"status": AgentStatus.ERROR.value, "error_log": [_sentinel()]}
    fields.update(overrides)
    return _state_after_a_successful_inner_run(**fields)


def _merge(state: dict, partial: dict) -> dict:
    merged = dict(state)
    for key, value in partial.items():
        if key in _ACCUMULATED:
            merged[key] = list(merged.get(key, [])) + list(value)
        else:
            merged[key] = value
    return merged


def _run(state: dict) -> tuple[dict, dict]:
    """Run post_process over `state`; return (merged state, caller envelope)."""
    node = PostProcessNode()
    errored = state.get("status") == AgentStatus.ERROR.value
    partial = node.execute(state) if errored else node(state)
    merged = _merge(state, partial)
    return merged, HENNGEAccessControlAgent().get_output(merged)


def _envelope(state: dict) -> dict:
    return _run(state)[1]


def _payload_with_nested_credential(field_name: str = "notes") -> str:
    return to_json(
        {"access_request": [{"user_id": _USER_ID, "attributes": [{"name": field_name, "values": [_bearer()]}]}]}
    )


# Factories, not shared dicts: every test gets a fresh state. Each seeds the
# sentinel into error_log so the walk below has something to find.
_REFUSED_STATES = [
    pytest.param(
        lambda: _state_after_a_successful_inner_run(
            error_log=[_sentinel()], hennge_payload=_payload_with_nested_credential()
        ),
        id="credential-nested-in-payload",
    ),
    pytest.param(
        lambda: _state_after_a_successful_inner_run(error_log=[_sentinel()], record_id="", record_ref=""),
        id="success-without-record-evidence",
    ),
    pytest.param(
        lambda: _state_after_a_successful_inner_run(
            error_log=[_sentinel()], hennge_payload=to_json({"access_request": [{_bearer(): "granted"}]})
        ),
        id="credential-shaped-mapping-key",
    ),
]
_NON_SUCCESS_STATES = [*_REFUSED_STATES, pytest.param(_state_after_a_failed_inner_run, id="inner-workflow-error")]


class TestErrorEnvelopeIsClosedSet:
    """On every non-success path the caller receives closed-set labels only."""

    @pytest.mark.parametrize("make_state", _NON_SUCCESS_STATES)
    def test_every_envelope_value_is_a_declared_constant(self, make_state):
        envelope = _envelope(make_state())

        assert envelope["status"] == AgentStatus.ERROR.value
        assert envelope["output"], "a falsy payload re-opens the `result` fallback"
        assert set(envelope["output"]) == {"reason"}, envelope["output"]
        assert set(envelope["output"].values()) <= ERROR_REASONS, envelope["output"]

    @pytest.mark.parametrize("make_state", _NON_SUCCESS_STATES)
    def test_sentinel_seeded_in_error_log_reaches_neither_the_envelope_nor_the_cleared_state(self, make_state):
        merged, envelope = _run(make_state())

        assert _fragments_found(envelope) == [], envelope
        # The internal channel still has the line - once, never re-emitted.
        assert merged["error_log"].count(_sentinel()) == 1
        # And it sits nowhere else in the merged state either.
        outside_the_log = {key: value for key, value in merged.items() if key != "error_log"}
        assert _fragments_found(outside_the_log) == [], outside_the_log

    def test_inner_error_envelope_carries_the_reason_code_only(self):
        """The inner workflow's error_log can carry upstream response text -
        names, identifiers, tokens. None of it, none of the record evidence,
        and none of the answer that was merged into `result`, reaches the
        caller."""
        merged, envelope = _run(_state_after_a_failed_inner_run())
        rendered = json.dumps(envelope, default=str)

        assert envelope["status"] == AgentStatus.ERROR.value
        assert envelope["output"] == {"reason": _REASON_WORKFLOW_FAILED}
        assert _RECORD_REF not in rendered
        assert _USER_ID not in rendered
        assert _APP_NAME not in rendered
        assert "Granted app access" not in rendered
        assert merged["error_log"] == [_sentinel()]

    def test_refusal_names_the_location_in_error_log_and_never_in_the_envelope(self):
        """The violation entry names a place, not a value, and it stays
        internal: it is written to error_log and never enters the envelope."""
        merged, envelope = _run(_state_after_a_successful_inner_run(hennge_payload=_payload_with_nested_credential()))
        reported = " ".join(merged["error_log"])
        rendered = json.dumps(envelope, default=str)

        assert envelope["output"] == {"reason": _REASON_OUTPUT_WITHHELD}
        assert _bearer() not in reported
        assert "hennge_payload.access_request[0].attributes[0].values[0]" in reported
        assert "output gate" not in rendered
        assert "hennge_payload" not in rendered
        assert _bearer() not in rendered

    def test_credential_shaped_key_is_withheld_from_the_label_with_the_clearing_intact(self):
        """A credential-shaped mapping KEY must not be quoted into the label:
        the label rides error_log, where the framework's own credential scan
        would raise on the node result and replace the cleared fields with a
        bare error - restoring the `result` fallback the clearing closed. The
        cleared `result` here is the proof that the scan did not fire."""
        state = _state_after_a_successful_inner_run(
            hennge_payload=to_json({"access_request": [{_bearer(): "granted"}]})
        )
        merged, envelope = _run(state)
        reported = " ".join(merged["error_log"])

        assert envelope["output"] == {"reason": _REASON_OUTPUT_WITHHELD}
        assert merged["result"] == ""
        assert _bearer() not in reported
        assert "<withheld>" in reported
        assert _bearer() not in json.dumps(envelope, default=str)

    def test_caller_field_name_never_reaches_the_envelope(self):
        """A caller's field name lands in the assembled payload as a value; a
        refusal that echoed anything of the payload would publish it, and a
        label that quoted the value would put it in error_log."""
        field_name = "A. Tanaka <a.tanaka@" + "example.com>"
        merged, envelope = _run(
            _state_after_a_successful_inner_run(hennge_payload=_payload_with_nested_credential(field_name))
        )
        rendered = json.dumps(envelope, default=str)

        assert envelope["output"] == {"reason": _REASON_OUTPUT_WITHHELD}
        assert "Tanaka" not in rendered
        assert "@example" not in rendered
        assert "Tanaka" not in " ".join(merged["error_log"])


class TestUnrefusedResponseStillShips:
    """CONTROL: a clean response is delivered intact - otherwise every
    containment assertion above would pass vacuously."""

    def test_clean_response_carries_the_answer(self):
        envelope = _envelope(_state_after_a_successful_inner_run())

        assert envelope["status"] == AgentStatus.SUCCESS.value
        out = envelope["output"]
        assert out["record_id"] == _RECORD_ID
        assert out["record_ref"] == _RECORD_REF
        assert out["user_id"] == _USER_ID
        assert out["app_name"] == _APP_NAME
        assert out["intent"] == "grant_access"
        assert out["confirmation"] == _CONFIRMATION

    def test_clean_response_carries_no_reason_code(self):
        envelope = _envelope(_state_after_a_successful_inner_run())
        rendered = json.dumps(envelope, default=str)

        assert "reason" not in envelope["output"]
        assert not any(reason in rendered for reason in ERROR_REASONS)


# ---------------------------------------------------------------------------
# Layer 2: the real ASGI /invoke entry point
# ---------------------------------------------------------------------------

_TOKEN = "pb-invoke-test-token"
_GRANT_REQUEST = 'Grant access to the app named "Salesforce" for the account below.'


@pytest.fixture(scope="module")
def client():
    os.environ["INVOKE_AUTH_TOKEN"] = _TOKEN
    with warnings.catch_warnings():
        # The sync test client wraps the ASGI app through a shim that emits a
        # deprecation notice on import in some fastapi/starlette combinations;
        # it is import-time noise from the client library, not app behaviour.
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import src.api.server as server

        with TestClient(server.app) as test_client:
            yield test_client


def _invoke(client, payload):
    return client.post("/invoke", json=payload, headers={"Authorization": f"Bearer {_TOKEN}"})


@pytest.fixture
def seen_by_post_process(monkeypatch) -> list:
    """Spy on the boundary node: the error_log it received, per call. Lets a
    test prove the seed arrived at the boundary before asserting it is absent
    from the body - a walk over a body that never carried the seed proves
    nothing."""
    seen: list = []
    original = PostProcessNode.execute

    def _spy(self, state):
        seen.append(list(state.get("error_log") or []))
        return original(self, state)

    monkeypatch.setattr(PostProcessNode, "execute", _spy)
    return seen


@pytest.fixture
def sentinel_seeded_by_the_inner_workflow(monkeypatch):
    """The last inner node adds the sentinel to error_log as a non-fatal note
    (status untouched), the way a node reports a recoverable upstream oddity.
    From there it travels the real path: inner get_output(), merge_output(),
    the outer reducer, post_process, finalize, the base envelope."""
    original = ConfirmNode.execute

    def _confirm_with_a_note(self, state):
        return {**original(self, state), "error_log": [_sentinel()]}

    monkeypatch.setattr(ConfirmNode, "execute", _confirm_with_a_note)


class TestInvokeBodyCarriesNoErrorText:
    def test_refused_response_carries_the_reason_code_only(
        self, client, monkeypatch, sentinel_seeded_by_the_inner_workflow, seen_by_post_process
    ):
        import src.nodes.post_process_node as post_process

        # Make the gate's recognizer fire on an ordinary application label, so
        # the refusal happens on a real success path rather than a synthetic one.
        monkeypatch.setattr(post_process, "_CREDENTIAL_LIKE_RE", re.compile("Salesforce"))

        response = _invoke(client, {"input": _GRANT_REQUEST, "input_context": {"user_id": "u-2044"}})
        assert response.status_code == 200
        body = response.json()

        assert body["status"] == AgentStatus.ERROR.value, body
        assert body["output"] == {"reason": _REASON_OUTPUT_WITHHELD}, body
        # The seed reached the boundary node, so the walk below is not vacuous.
        assert seen_by_post_process and any(_sentinel() in line for line in seen_by_post_process[0])
        assert _fragments_found(body) == [], body
        assert "error_log" not in body
        for text in _strings_in(body):
            assert "output gate" not in text
            assert "Salesforce" not in text
            assert "hennge://" not in text
            assert "u-2044" not in text

    def test_inner_failure_ships_no_error_text(self, client, monkeypatch, seen_by_post_process):
        def _fail(self, state, config=None):
            return {"status": AgentStatus.ERROR.value, "error_log": [_sentinel()]}

        monkeypatch.setattr(CallHenngeApiNode, "execute", _fail)

        response = _invoke(client, {"input": _GRANT_REQUEST, "input_context": {"user_id": "u-2044"}})
        assert response.status_code == 200
        body = response.json()

        assert body["status"] == AgentStatus.ERROR.value, body
        assert not body.get("output")
        assert "error_log" not in body
        assert _fragments_found(body) == [], body
        # The backbone routes an inner error straight to finalize: the
        # boundary node did not run, and the base envelope carries no log.
        assert seen_by_post_process == []

    def test_clean_response_is_the_control(self, client, sentinel_seeded_by_the_inner_workflow, seen_by_post_process):
        response = _invoke(client, {"input": _GRANT_REQUEST, "input_context": {"user_id": "u-2044"}})
        assert response.status_code == 200
        body = response.json()

        assert body["status"] == AgentStatus.SUCCESS.value, body
        assert body["output"]["record_ref"].startswith("hennge://access-grants/")
        assert "u-2044" in body["output"]["confirmation"]
        # The note reached the boundary and still never reaches the caller:
        # error_log is not projected on the success path either.
        assert seen_by_post_process and any(_sentinel() in line for line in seen_by_post_process[0])
        assert "error_log" not in body
        assert _fragments_found(body) == [], body
