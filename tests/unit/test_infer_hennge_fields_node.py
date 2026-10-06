# CMN-C2-282 - Unit tests: InferHenngeFieldsNode (inner Step 3)
#
# Canon: invoked via node(state), so the framework's full security pipeline runs
# (trust gate -> input gate -> execute() -> output gate); inner domain node ->
# caller_trust_level = TrustLevel.ANONYMOUS.value.
# Positive payloads are PII-free: the framework's mask rewrites Title-Case
# bigrams in validated_input, so quoted app names use a single word and
# "Key: value" attribute values stay lower-case.
#
# app_name is the one field a model-backed override can supply (see the module
# docstring); user_id and attributes stay deterministic regardless.

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.infer_hennge_fields_node import InferHenngeFieldsNode
from src.schemas.state import from_json


class FakeLLM:
    """Test double for the LLM client - exposes only complete(messages) -> {"content": ...}."""

    def __init__(self, content=None, raises=None):
        self._content = content
        self._raises = raises

    def complete(self, messages):
        if self._raises is not None:
            raise self._raises
        return {"content": self._content}


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    monkeypatch.setattr("src.nodes.infer_hennge_fields_node.emit_trace_event", lambda *a, **k: None)


def _state(text: str, intent: str = "lookup_access", user_hint: str = "", **overrides) -> dict:
    state = {
        "validated_input": text,
        "intent": intent,
        "user_hint": user_hint,
        "caller_trust_level": TrustLevel.ANONYMOUS.value,
        "correlation_id": "infer-fields-test",
        "node_history": [],
        "error_log": [],
        "execution_time": {},
    }
    state.update(overrides)
    return state


class TestInferHenngeFieldsNode:
    def setup_method(self):
        self.node = InferHenngeFieldsNode()

    def test_lookup_extracts_id_from_text(self):
        result = self.node(
            _state("Look up the app access status for user id u-1001 and summarize the current assignments on file.")
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["user_id"] == "u-1001"
        # hennge_payload is stored as a JSON string, not a native dict.
        assert isinstance(result["hennge_payload"], str)
        assert from_json(result["hennge_payload"], {}) == {"user_id": "u-1001"}

    def test_id_shaped_hint_used_when_text_has_no_id(self):
        result = self.node(_state("Summarize the current app assignments on file", user_hint="u-2044"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["user_id"] == "u-2044"
        assert from_json(result["hennge_payload"], {}) == {"user_id": "u-2044"}

    def test_id_resolved_from_account_field_line(self):
        # "Account: <id>" resolves via the Key: value field path (_ID_KEYS) -
        # the in-text regex needs "account id"/"account code", so this line is
        # only reachable through the parsed fields.
        result = self.node(_state("Summarize the assignments on file\nAccount: u-3003"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["user_id"] == "u-3003"

    def test_grant_builds_access_request_payload(self):
        # Attribute values stay lower-case: the framework's name mask rewrites
        # Title-Case word pairs even ACROSS newlines before execute() sees the text.
        text = 'grant access to "Salesforce" for user id u-1001\nDepartment: sales\nGrade: 3'
        result = self.node(_state(text, intent="grant_access"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["user_id"] == "u-1001"
        assert result["app_name"] == "Salesforce"
        payload = from_json(result["hennge_payload"], {})
        record = payload["access_request"][0]
        assert record["user_id"] == "u-1001"
        assert record["app_name"] == "Salesforce"
        assert {"name": "Department", "values": ["sales"]} in record["attributes"]
        assert {"name": "Grade", "values": ["3"]} in record["attributes"]

    def test_revoke_builds_access_request_with_app_field(self):
        # App name via the "App: ..." field line (_APP_KEYS); the App/Account id
        # keys themselves never leak into the attributes list.
        text = "revoke the app access for user id u-1001\nApp: salesforce"
        result = self.node(_state(text, intent="revoke_access"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["app_name"] == "salesforce"
        payload = from_json(result["hennge_payload"], {})
        record = payload["access_request"][0]
        assert record["user_id"] == "u-1001"
        assert record["app_name"] == "salesforce"
        assert "attributes" not in record

    def test_check_policy_is_readonly_payload(self):
        result = self.node(_state("check the policy for user id u-1001", intent="check_policy"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert from_json(result["hennge_payload"], {}) == {"user_id": "u-1001"}

    def test_unresolved_id_left_empty_never_invented(self):
        result = self.node(_state("Summarize the current app assignments on file"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["user_id"] == ""
        assert from_json(result["hennge_payload"], {}) == {"user_id": ""}

    def test_non_id_shaped_hint_left_unresolved(self):
        result = self.node(_state("Summarize the assignments", user_hint="not a valid id!"))
        assert result["user_id"] == ""

    def test_missing_input_errors(self):
        result = self.node(_state(""))
        assert result["status"] == AgentStatus.ERROR.value
        assert result["error_log"]


class TestInferHenngeFieldsNodeLlmPath:
    """Model-backed app_name override, malformed-response and failure paths.

    user_id is asserted unaffected in every case - the LLM double never even
    returns one, and the node never asks it for one (see the module docstring).
    """

    def test_llm_override_on_well_formed_json(self):
        # No quoted name / App: field in the text at all - heuristic app_name
        # would be empty; the LLM's answer fills it in.
        node = InferHenngeFieldsNode(llm=FakeLLM(content='{"app_name": "internal wiki"}'))
        result = node(_state("give her access to the internal wiki please", user_hint="u-1001"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["app_name"] == "internal wiki"
        assert result["user_id"] == "u-1001"  # unaffected - never LLM-derived

    def test_llm_response_wrapped_in_prose_or_fences_still_parses(self):
        node = InferHenngeFieldsNode(llm=FakeLLM(content='```json\n{"app_name": "Payroll"}\n```'))
        result = node(_state("look into her current assignments", user_hint="u-1001"))
        assert result["app_name"] == "Payroll"

    def test_llm_null_app_name_falls_back_to_heuristic(self):
        node = InferHenngeFieldsNode(llm=FakeLLM(content='{"app_name": null}'))
        text = 'grant access to "Salesforce" for user id u-1001'
        result = node(_state(text, intent="grant_access"))
        assert result["app_name"] == "Salesforce"  # quoted-name heuristic, unaffected
        assert result["user_id"] == "u-1001"

    def test_llm_malformed_json_falls_back_to_heuristic(self):
        node = InferHenngeFieldsNode(llm=FakeLLM(content="not json at all"))
        text = 'revoke the app access for user id u-1001\nApp: salesforce'
        result = node(_state(text, intent="revoke_access"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["app_name"] == "salesforce"
        assert result["user_id"] == "u-1001"

    def test_llm_raising_falls_back_to_heuristic(self):
        node = InferHenngeFieldsNode(llm=FakeLLM(raises=RuntimeError("upstream API error")))
        text = 'grant access to "Salesforce" for user id u-1001'
        result = node(_state(text, intent="grant_access"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["app_name"] == "Salesforce"
        assert result["user_id"] == "u-1001"

    def test_llm_can_never_supply_a_user_id(self):
        # Even if a real client's response smuggled a user_id-shaped key, this
        # node never reads it - only "app_name" is ever pulled from the parsed
        # LLM response (see _infer_app_name_via_llm).
        node = InferHenngeFieldsNode(llm=FakeLLM(content='{"app_name": "Payroll", "user_id": "u-9999"}'))
        result = node(_state("give her access to it please", user_hint="u-1001"))
        assert result["user_id"] == "u-1001"

    def test_no_llm_injected_and_no_secret_bound_falls_back_to_heuristic(self):
        # The real production shape in any environment without a configured
        # Azure OpenAI key.
        node = InferHenngeFieldsNode()
        text = 'grant access to "Salesforce" for user id u-1001'
        result = node(_state(text, intent="grant_access"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["app_name"] == "Salesforce"

    def test_empty_input_never_calls_the_llm(self):
        calls = []

        class _CountingLLM(FakeLLM):
            def complete(self, messages):
                calls.append(messages)
                return super().complete(messages)

        node = InferHenngeFieldsNode(llm=_CountingLLM(content='{"app_name": "Payroll"}'))
        result = node(_state(""))
        assert result["status"] == AgentStatus.ERROR.value
        assert calls == []
