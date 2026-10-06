# CMN-C2-282 - Unit tests: ClassifyIntentNode (inner Step 2)
# Intents: lookup_access / grant_access / revoke_access / check_policy.
# The deterministic keyword heuristic is always computed as the baseline/
# fallback; an injected (or, in production, a real Azure OpenAI) LLM
# classification overrides it when available and well-formed. Unknown from
# either source falls back to the read-only lookup_access.
#
# Canon: invoked via node(state), so the framework's full security pipeline runs
# (trust gate -> input gate -> execute() -> output gate); inner domain node ->
# caller_trust_level = TrustLevel.ANONYMOUS.value.

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.classify_intent_node import ClassifyIntentNode


class FakeLLM:
    """Test double for the LLM client - exposes only complete(messages) -> {"content": ...}.

    Production wiring never passes one; only used here to exercise the
    override / malformed-response / raising paths without a real network call.
    """

    def __init__(self, content=None, raises=None):
        self._content = content
        self._raises = raises

    def complete(self, messages):
        if self._raises is not None:
            raise self._raises
        return {"content": self._content}


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    monkeypatch.setattr("src.nodes.classify_intent_node.emit_trace_event", lambda *a, **k: None)


def _state(text: str) -> dict:
    return {
        "validated_input": text,
        "caller_trust_level": TrustLevel.ANONYMOUS.value,
        "correlation_id": "classify-intent-test",
        "node_history": [],
        "error_log": [],
        "execution_time": {},
    }


class TestClassifyIntentNode:
    def setup_method(self):
        self.node = ClassifyIntentNode()

    def test_keyword_lookup_access(self):
        result = self.node(_state("Look up the app access status for user id u-1001."))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["intent"] == "lookup_access"

    def test_keyword_grant_access(self):
        result = self.node(_state('grant access to "Salesforce" for user id u-1001'))
        assert result["intent"] == "grant_access"

    def test_keyword_revoke_access(self):
        result = self.node(_state('revoke the access to "Salesforce" for user id u-1001'))
        assert result["intent"] == "revoke_access"

    def test_keyword_check_policy(self):
        result = self.node(_state("check the sign-in policy assignments for user id u-1001"))
        assert result["intent"] == "check_policy"

    def test_write_keyword_wins_over_lookup(self):
        # Priority order is writes-first: a "revoke ... then show the status"
        # style request classifies as the write, never the read.
        result = self.node(_state("revoke the app access for user id u-1001 and show the status"))
        assert result["intent"] == "revoke_access"

    def test_policy_outranks_generic_lookup(self):
        # "check the policy" must not be swallowed by the lookup keywords.
        result = self.node(_state("show the policy for user id u-1001"))
        assert result["intent"] == "check_policy"

    def test_no_signal_defaults_to_readonly_lookup(self):
        result = self.node(_state("please handle this for the team"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["intent"] == "lookup_access"
        # Non-fatal low-confidence note travels in error_log; status stays SUCCESS.
        assert any("defaulted to lookup_access" in entry for entry in result.get("error_log", []))

    def test_empty_input_errors(self):
        result = self.node(_state(""))
        assert result["status"] == AgentStatus.ERROR.value
        assert result["error_log"]

    def test_audit_event_carries_the_intent_label_only(self, monkeypatch):
        events = []
        monkeypatch.setattr(
            "src.nodes.classify_intent_node.emit_trace_event",
            lambda *args, **kwargs: events.append(args),
        )
        self.node(_state("Look up the app access status for user id u-1001."))
        payloads = {args[0]: args[1] for args in events}
        # Emit-spy asserts on the payload (args[1]) - the label, never the text.
        assert payloads["classify_intent_complete"]["intent"] == "lookup_access"
        assert payloads["classify_intent_complete"]["defaulted"] is False
        assert payloads["classify_intent_complete"]["source"] == "keyword"


class TestClassifyIntentNodeLlmPath:
    """Model-backed classification override, malformed-response and failure paths."""

    def test_llm_override_on_well_formed_json(self):
        # Keyword heuristic alone would say lookup_access ("show"); the LLM's
        # (well-formed) answer overrides it.
        node = ClassifyIntentNode(llm=FakeLLM(content='{"intent": "grant_access"}'))
        result = node(_state("show her the marketing dashboard please"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["intent"] == "grant_access"

    def test_llm_response_wrapped_in_prose_or_fences_still_parses(self):
        node = ClassifyIntentNode(llm=FakeLLM(content='Sure, here it is:\n```json\n{"intent": "check_policy"}\n```'))
        result = node(_state("what applies to this user"))
        assert result["intent"] == "check_policy"

    def test_llm_out_of_set_intent_falls_back_to_keyword(self):
        node = ClassifyIntentNode(llm=FakeLLM(content='{"intent": "delete_everything"}'))
        result = node(_state('grant access to "Salesforce" for user id u-1001'))
        assert result["intent"] == "grant_access"  # keyword result, LLM's answer rejected

    def test_llm_malformed_json_falls_back_to_keyword(self):
        node = ClassifyIntentNode(llm=FakeLLM(content="not json at all"))
        result = node(_state('revoke the access to "Salesforce" for user id u-1001'))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["intent"] == "revoke_access"  # keyword fallback, no hard error

    def test_llm_raising_falls_back_to_keyword(self):
        node = ClassifyIntentNode(llm=FakeLLM(raises=RuntimeError("upstream API error")))
        result = node(_state("check the sign-in policy assignments for user id u-1001"))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["intent"] == "check_policy"

    def test_no_llm_injected_and_no_secret_bound_falls_back_to_keyword(self):
        # The real production shape in any environment without a configured
        # Azure OpenAI key: InvocationContext.from_state()/ctx.secrets.require()
        # fails, caught by the broad except, degrading to the keyword result.
        node = ClassifyIntentNode()
        result = node(_state('grant access to "Salesforce" for user id u-1001'))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["intent"] == "grant_access"

    def test_empty_input_never_calls_the_llm(self):
        calls = []

        class _CountingLLM(FakeLLM):
            def complete(self, messages):
                calls.append(messages)
                return super().complete(messages)

        node = ClassifyIntentNode(llm=_CountingLLM(content='{"intent": "grant_access"}'))
        result = node(_state(""))
        assert result["status"] == AgentStatus.ERROR.value
        assert calls == []

    def test_audit_event_source_is_llm_when_llm_wins(self, monkeypatch):
        events = []
        monkeypatch.setattr(
            "src.nodes.classify_intent_node.emit_trace_event",
            lambda *args, **kwargs: events.append(args),
        )
        node = ClassifyIntentNode(llm=FakeLLM(content='{"intent": "check_policy"}'))
        node(_state("please handle this for the team"))
        payloads = {args[0]: args[1] for args in events}
        assert payloads["classify_intent_complete"]["source"] == "llm"
