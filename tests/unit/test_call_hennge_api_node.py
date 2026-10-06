# CMN-C2-282 - Unit tests: CallHenngeApiNode (inner Step 4, tool side-effect)
#
# Canon: invoked via node(state), so the framework's full security pipeline runs
# (trust gate -> input gate -> execute() -> output gate); inner domain node ->
# caller_trust_level = TrustLevel.ANONYMOUS.value.
# The ONE documented exception: the config-override call passes a 2nd (config)
# argument, which __call__ cannot forward - that single test stays a DIRECT
# execute(state, config=...) call (ANONYMOUS node, the trust gate is unaffected).
#
# The node builds its client locally (SDK v1 nodes are no-arg), so error-path
# transports are exercised by monkeypatching the module's HenngeClient symbol
# (our own module attribute - never a sys.modules stub of shared.*).

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from shared.secrets.inmemory_provider import InMemoryProvider

from src.nodes.call_hennge_api_node import CallHenngeApiNode
from src.services.hennge_client import HenngeApiError
from src.schemas.state import to_json


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    monkeypatch.setattr("src.nodes.call_hennge_api_node.emit_trace_event", lambda *a, **k: None)


def _state(**overrides) -> dict:
    state = {
        "hennge_payload": to_json({"user_id": "u-1001"}),
        "intent": "lookup_access",
        "user_id": "u-1001",
        "caller_trust_level": TrustLevel.ANONYMOUS.value,
        "correlation_id": "call-hennge-test",
        "session_id": "s1",
        "thread_id": "th1",
        "trace_id": "t1",
        "node_history": [],
        "error_log": [],
        "execution_time": {},
    }
    state.update(overrides)
    return state


class _FakeErrorClient:
    """Stands in for HenngeClient: lookup raises the documented API error."""

    def __init__(self, *args, **kwargs):
        pass

    uses_stub_transport = True

    def get_user_access(self, user_id, api_token):
        raise HenngeApiError(403, "forbidden by integration permissions")


class _FakeLiveClient:
    """Stands in for HenngeClient with a LIVE (non-stub) transport."""

    captured: dict = {}

    def __init__(self, *args, **kwargs):
        pass

    uses_stub_transport = False

    def get_user_access(self, user_id, api_token):
        _FakeLiveClient.captured = {"user_id": user_id, "api_token": api_token}
        return {"access_data": [{"app_id": "app-1", "app_name": "app-1", "status": "active"}]}


class TestCallHenngeApiNode:
    def setup_method(self):
        self.node = CallHenngeApiNode()

    def test_lookup_success_via_default_v1_stub(self):
        # Default transport = deterministic, network-free v1 stub; no secret
        # provider bound -> the node runs on the documented stub placeholder.
        result = self.node(_state())
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["record_id"] == "u-1001"
        assert result["record_ref"] == "hennge://users/u-1001/applications"
        assert result["user_id"] == "u-1001"
        assert result["app_name"]  # first access entry's app label surfaces

    def test_check_policy_success_via_default_v1_stub(self):
        state = _state(intent="check_policy")
        result = self.node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["record_id"] == "u-1001"
        assert result["record_ref"] == "hennge://users/u-1001/policies"

    def test_grant_success_via_default_v1_stub(self):
        state = _state(
            intent="grant_access",
            hennge_payload=to_json({"access_request": [{"user_id": "u-1001", "app_name": "Salesforce"}]}),
        )
        result = self.node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["record_id"].startswith("g-")
        assert result["record_ref"] == f"hennge://access-grants/{result['record_id']}"

    def test_revoke_success_via_default_v1_stub(self):
        state = _state(
            intent="revoke_access",
            hennge_payload=to_json({"access_request": [{"user_id": "u-1001", "app_name": "Salesforce"}]}),
        )
        result = self.node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["record_id"].startswith("r-")
        assert result["record_ref"] == f"hennge://access-revocations/{result['record_id']}"

    def test_hennge_config_state_field_sets_base_url(self):
        # The inner graph injects the manifest `hennge:` section as the JSON
        # hennge_config state field; the stub transport still serves the call.
        state = _state(hennge_config=to_json({"base_url": "https://hennge.example.test/v1"}))
        result = self.node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["record_ref"] == "hennge://users/u-1001/applications"

    def test_config_override_direct_execute_call(self):
        # Documented canon exception: execute(state, config=...) takes a 2nd
        # argument that __call__ cannot forward, so this ONE test calls execute
        # directly (ANONYMOUS node - the trust gate is not the subject here).
        config = {"configurable": {"hennge": {"base_url": "https://hennge.example.test/v1"}}}
        result = self.node.execute(_state(), config=config)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["record_id"] == "u-1001"

    def test_missing_payload_errors(self):
        result = self.node(_state(hennge_payload=None))
        assert result["status"] == AgentStatus.ERROR.value
        assert result["error_log"]

    def test_lookup_with_unresolved_id_errors(self):
        state = _state(user_id="", hennge_payload=to_json({"user_id": ""}))
        result = self.node(state)
        assert result["status"] == AgentStatus.ERROR.value
        assert any("unresolved user id" in entry for entry in result["error_log"])

    def test_revoke_with_unresolved_id_errors(self):
        state = _state(
            intent="revoke_access",
            user_id="",
            hennge_payload=to_json({"access_request": [{"user_id": ""}]}),
        )
        result = self.node(state)
        assert result["status"] == AgentStatus.ERROR.value

    def test_unknown_intent_errors(self):
        result = self.node(_state(intent="delete_access"))
        assert result["status"] == AgentStatus.ERROR.value
        assert any("unknown intent" in entry for entry in result["error_log"])

    def test_api_error_surfaces_status_error(self, monkeypatch):
        monkeypatch.setattr("src.nodes.call_hennge_api_node.HenngeClient", _FakeErrorClient)
        result = self.node(_state())
        assert result["status"] == AgentStatus.ERROR.value
        assert any("403" in entry for entry in result["error_log"])

    def test_live_transport_without_secret_refuses_call(self, monkeypatch):
        # With a LIVE transport a missing HENNGE_API_TOKEN is a hard error -
        # a real API is never called unauthenticated.
        monkeypatch.setattr("src.nodes.call_hennge_api_node.HenngeClient", _FakeLiveClient)
        result = self.node(_state())
        assert result["status"] == AgentStatus.ERROR.value
        assert any("unauthenticated" in entry for entry in result["error_log"])

    def test_live_transport_reads_token_from_ctx_secrets(self, monkeypatch):
        monkeypatch.setattr("src.nodes.call_hennge_api_node.HenngeClient", _FakeLiveClient)
        _FakeLiveClient.captured = {}
        with bound_secrets(InMemoryProvider({"HENNGE_API_TOKEN": "mock-token-for-testing"})):
            result = self.node(_state())
        assert result["status"] == AgentStatus.SUCCESS.value
        assert _FakeLiveClient.captured["api_token"] == "mock-token-for-testing"
        assert _FakeLiveClient.captured["user_id"] == "u-1001"

    def test_audit_event_carries_side_effect_signals_only(self, monkeypatch):
        events = []
        monkeypatch.setattr(
            "src.nodes.call_hennge_api_node.emit_trace_event",
            lambda *args, **kwargs: events.append(args),
        )
        self.node(_state())
        payloads = {args[0]: args[1] for args in events}
        # Emit-spy asserts on the payload (args[1]) - presence signals only.
        payload = payloads["call_hennge_api_complete"]
        assert payload["intent"] == "lookup_access"
        assert payload["has_record_id"] is True
        assert payload["stub_transport"] is True
