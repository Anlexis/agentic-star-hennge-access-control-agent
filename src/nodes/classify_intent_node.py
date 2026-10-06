"""Inner workflow Step 2: ClassifyIntent.

Classifies the (redacted) request into one of lookup_access / grant_access /
revoke_access / check_policy. The deterministic keyword heuristic is the
baseline - always computed, so the template stays testable and runnable
without a language model - and an LLM classification (model-backed synthesis,
see docs/02_design.md "Implementation Note") overrides it when available and
well-formed. Any LLM failure (no secret bound, API error, malformed response)
silently falls back to the keyword result; low-confidence / unknown from
EITHER source falls back to the read-only "lookup_access" default with a
note - never a write.
"""

from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.services.llm.azure_openai_client import AzureOpenAIClient
from shared.utils.audit_logger import emit_trace_event
from shared.utils.llm_json import extract_json_object

_VALID_INTENTS = ("lookup_access", "grant_access", "revoke_access", "check_policy")

_CLASSIFY_SYSTEM_PROMPT = """\
You classify a HENNGE One access-control request into exactly one intent.

Valid intents:
- lookup_access: look up / show / summarize a user's current app access or assignments
- grant_access: give / provision / enable a user's access to an app
- revoke_access: remove / deactivate / disable a user's access to an app
- check_policy: check a user's policy assignments

If the request is ambiguous or does not clearly match one of these, respond
with "lookup_access" (the safe, read-only default) - never guess a write
intent (grant_access / revoke_access) without a clear, explicit signal.

Respond with a JSON object containing only the key "intent", e.g.
{"intent": "lookup_access"}. No other text.
"""

# Deterministic keyword signals (checked in priority order, writes first so a
# "revoke it then show the status" style request classifies as the write; the
# policy check outranks the generic lookup so "check the policy" is not
# swallowed by the lookup keywords).
_KEYWORDS = (
    (
        "revoke_access",
        (
            "revoke",
            "remove access",
            "remove the access",
            "deactivate",
            "disable access",
            "unassign",
            "deprovision",
            "take away",
            "剥奪",
            "解除",
            "無効化",
            "停止",
        ),
    ),
    (
        "grant_access",
        (
            "grant",
            "give access",
            "give the access",
            "allow access",
            "enable access",
            "provision",
            "assign access",
            "add access",
            "付与",
            "許可",
            "有効化",
            "割り当て",
        ),
    ),
    ("check_policy", ("policy", "policies", "ポリシー")),
    (
        "lookup_access",
        (
            "look up",
            "lookup",
            "find",
            "show",
            "get",
            "fetch",
            "retrieve",
            "search",
            "list",
            "summarize",
            "access status",
            "what access",
            "which apps",
            "who has",
            "照会",
            "検索",
            "参照",
            "確認",
        ),
    ),
)


class ClassifyIntentNode(FunctionNode):
    """Classify the request into a HENNGE access-control operation intent."""

    # Inner domain node, read-only classification of already-redacted text -
    # the external trust gate lives on the outer backbone pre_process.
    required_trust_level = TrustLevel.ANONYMOUS

    def __init__(self, llm: Any = None) -> None:
        super().__init__()
        # Test-double seam only - production wiring (register_nodes()) never
        # passes one; a real client is built fresh per invocation in
        # _resolve_llm(), never cached here (nodes are constructed once and
        # reused across every invocation via the registry's LRU cache).
        self._llm = llm

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        text = state.get("validated_input", "") or ""
        if not text:
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["ClassifyIntentNode: missing validated_input"],
            }

        keyword_intent = self._classify_via_keywords(text)
        llm_intent = self._classify_via_llm(text, state)
        used_llm = llm_intent is not None
        intent = llm_intent if used_llm else keyword_intent

        note: list[str] = []
        if intent not in _VALID_INTENTS:
            note = ["ClassifyIntentNode: low-confidence classification, " "defaulted to lookup_access (read-only)"]
            intent = "lookup_access"

        # Audit the classification decision - intent label + source only, never the text.
        emit_trace_event(
            "classify_intent_complete",
            {"intent": intent, "defaulted": bool(note), "source": "llm" if used_llm else "keyword"},
            state,
        )

        result = {"intent": intent, "status": AgentStatus.SUCCESS.value}
        if note:
            result["error_log"] = note  # non-fatal note; status stays SUCCESS
        return result

    # -- classification -------------------------------------------------------

    def _classify_via_keywords(self, text: str) -> str:
        low = text.lower()
        for intent, words in _KEYWORDS:
            if any(w in low for w in words):
                return intent
        # No signal at all: fall through to the read-only default via the
        # _VALID_INTENTS guard in execute() (returns a sentinel outside the set).
        return "unknown"

    def _classify_via_llm(self, text: str, state: dict[str, Any]) -> "str | None":
        """Model-backed classification; None on ANY failure (never raises).

        Missing/invalid secret, API error, or a malformed/out-of-set response
        all degrade the same way - the caller falls back to the keyword
        result, never to a hard node error.
        """
        try:
            llm = self._resolve_llm(state)
            response = llm.complete(
                [
                    {"role": "system", "content": _CLASSIFY_SYSTEM_PROMPT},
                    {"role": "user", "content": text},
                ]
            )
            parsed = extract_json_object(response.get("content"))
            intent = parsed.get("intent")
            return intent if intent in _VALID_INTENTS else None
        except Exception:
            return None

    def _resolve_llm(self, state: dict[str, Any]) -> Any:
        if self._llm is not None:
            return self._llm
        ctx = InvocationContext.from_state(state)
        return AzureOpenAIClient(
            {
                "api_key": ctx.secrets.require("AZURE_OPENAI_API_KEY"),
                "azure_endpoint": ctx.secrets.require("AZURE_OPENAI_ENDPOINT"),
                "azure_deployment": ctx.secrets.require("AZURE_OPENAI_DEPLOYMENT"),
            }
        )
