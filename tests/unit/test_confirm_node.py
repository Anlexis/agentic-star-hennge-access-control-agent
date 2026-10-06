# CMN-C2-282 - Unit tests: ConfirmNode (inner Step 5)
#
# Canon: invoked via node(state), so the framework's full security pipeline runs
# (trust gate -> input gate -> execute() -> output gate); inner domain node ->
# caller_trust_level = TrustLevel.ANONYMOUS.value.

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.confirm_node import ConfirmNode


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    monkeypatch.setattr("src.nodes.confirm_node.emit_trace_event", lambda *a, **k: None)


def _state(**overrides) -> dict:
    state = {
        "record_id": "u-1001",
        "record_ref": "hennge://users/u-1001/applications",
        "user_id": "u-1001",
        "app_name": "Salesforce",
        "intent": "lookup_access",
        "caller_trust_level": TrustLevel.ANONYMOUS.value,
        "correlation_id": "confirm-test",
        "node_history": [],
        "error_log": [],
        "execution_time": {},
    }
    state.update(overrides)
    return state


class TestConfirmNode:
    def setup_method(self):
        self.node = ConfirmNode()

    def test_lookup_confirmation(self):
        result = self.node(_state())
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "Retrieved app access status" in result["confirmation"]
        assert "'Salesforce'" in result["confirmation"]
        assert "user=u-1001" in result["confirmation"]
        assert "ref=hennge://users/u-1001/applications" in result["confirmation"]
        assert "id=u-1001" in result["confirmation"]
        assert result["result"]["record_id"] == "u-1001"
        assert result["result"]["record_ref"] == "hennge://users/u-1001/applications"

    def test_grant_verb(self):
        result = self.node(
            _state(intent="grant_access", record_id="g-12ab34cd", record_ref="hennge://access-grants/g-12ab34cd")
        )
        assert "Granted app access" in result["confirmation"]

    def test_revoke_verb(self):
        result = self.node(
            _state(intent="revoke_access", record_id="r-12ab34cd", record_ref="hennge://access-revocations/r-12ab34cd")
        )
        assert "Revoked app access" in result["confirmation"]

    def test_check_policy_verb(self):
        result = self.node(_state(intent="check_policy", record_ref="hennge://users/u-1001/policies"))
        assert "Retrieved policy assignments" in result["confirmation"]

    def test_unknown_intent_uses_generic_verb(self):
        result = self.node(_state(intent="mystery"))
        assert "Processed access-control request" in result["confirmation"]

    def test_id_only_no_ref(self):
        result = self.node(_state(record_ref=""))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "id=u-1001" in result["confirmation"]
        assert "ref=" not in result["confirmation"]

    def test_falls_back_to_user_id_when_app_missing(self):
        result = self.node(_state(app_name=""))
        assert "'u-1001'" in result["confirmation"]

    def test_missing_record_evidence_errors(self):
        result = self.node(_state(record_id="", record_ref=""))
        assert result["status"] == AgentStatus.ERROR.value
        assert result["error_log"]
