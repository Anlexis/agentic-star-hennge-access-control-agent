"""Inner workflow Step 3: InferHenngeFields.

Extracts the HENNGE user id, target application name, and "Key: value"
attribute fields from the (redacted) request and assembles a validated HENNGE
One Admin REST API request body for the classified intent. The user id is
taken only from an explicit id in the text or the caller-supplied user_hint -
an unresolved id is left empty rather than invented (risk mitigation: never
grant/revoke access on the wrong user account; the executor surfaces the miss
as status=error). This stays true with model-backed synthesis in the mix: the
LLM is NEVER consulted for user id, and its user_id output (if any) is
ignored - only the deterministic, text-anchored resolution below can ever
populate it.

Every value extracted here can end up in the caller-facing confirmation, so the
identifier is shape-locked and the application label is filtered to a
renderable alphabet before it leaves this node. Attribute (Key: value)
extraction stays deterministic - those values populate the actual HENNGE API
request body, so free-text invention there is a real-world side-effect risk,
not just a confirmation-message cosmetic one. Application-name extraction is
the one field enhanced by an LLM (model-backed synthesis, see
docs/02_design.md "Implementation Note"): the regex/quote-based heuristic is
the baseline - always computed - and the LLM overrides it when available and
well-formed (still filtered through the same renderable-alphabet gate before
it can reach the confirmation or the request body). Any LLM failure (no
secret bound, API error, malformed response) silently falls back to the
heuristic result.
"""

import re
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.services.llm.azure_openai_client import AzureOpenAIClient
from shared.utils.audit_logger import emit_trace_event
from shared.utils.llm_json import extract_json_object

from src.schemas.state import to_json
from src.services.security import to_inert_label

_APP_NAME_SYSTEM_PROMPT = """\
Extract ONLY the target application/service name from a HENNGE One
access-control request (e.g. "the marketing dashboard", "Salesforce",
"internal wiki"). Do not extract a user id, account id, or any other field.

Respond with a JSON object containing only the key "app_name" - a short
plain-text label, or null if no application is named. No other text.
"""

# A HENNGE user id: short alphanumeric identifier (no spaces), e.g. u-1001.
_ID_SHAPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,19}$")
# Explicit id mention in the request text, EN or JA
# ("user id u-1001" / "account id: u-2044" / "ユーザーID u-1001").
_ID_IN_TEXT_RE = re.compile(
    r"(?:user|account|member)\s+(?:id|code)\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9_-]{0,19})"
    r"|(?:ユーザーID|アカウントID|利用者ID)\s*[:：#]?\s*([A-Za-z0-9][A-Za-z0-9_-]{0,19})",
    re.IGNORECASE,
)
# Quoted application name: app "Foo" / to "Foo" / named "Foo". Curly quotes
# included so pasted rich-text requests still match.
_APP_QUOTED_RE = re.compile(r'(?:app|application|named|called|for|to)\s+["“]([^"”\n]+)["”]', re.IGNORECASE)
# "Key: value" attribute lines (ASCII or full-width colon). CJK ranges:
# hiragana/katakana + CJK unified ideographs.
_KV_RE = re.compile(r"^\s*([A-Za-z぀-ヿ一-鿿][\w \-぀-ヿ一-鿿]{0,40})[:：]\s*(.+?)\s*$")
# Keys that are the user id / app name themselves, not custom attributes.
_ID_KEYS = ("user id", "user", "account", "account id", "id", "user code")
_APP_KEYS = ("app", "app name", "application", "application name")


class InferHenngeFieldsNode(FunctionNode):
    """Extract entities and assemble the HENNGE One Admin REST API request body."""

    # Inner domain node - derives fields from already-validated text; the
    # external trust gate lives on the outer backbone pre_process.
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
        intent = state.get("intent", "lookup_access") or "lookup_access"
        user_hint = state.get("user_hint", "") or ""

        if not text.strip():
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["InferHenngeFieldsNode: missing validated_input"],
            }

        fields = self._parse_fields(text)
        # user_id is NEVER LLM-derived (risk mitigation above) - always the
        # deterministic, text-anchored resolution.
        user_id = self._resolve_id(text, user_hint, fields)
        app_name = self._resolve_app(text, fields)

        llm_app_name = self._infer_app_name_via_llm(text, state)
        used_llm = llm_app_name is not None
        if llm_app_name is not None:
            app_name = to_inert_label(llm_app_name)

        emit_trace_event(
            "infer_hennge_fields_app_name_source",
            {"source": "llm" if used_llm else "heuristic"},
            state,
        )

        if intent in ("grant_access", "revoke_access"):
            payload = self._build_access_request(user_id, app_name, fields)
        else:  # lookup_access / check_policy (read-only)
            payload = {"user_id": user_id}

        # Audit the assembled payload shape - field signals only, not content.
        emit_trace_event(
            "infer_hennge_fields_complete",
            {"intent": intent, "has_user_id": bool(user_id), "n_fields": len(fields)},
            state,
        )

        return {
            "user_id": user_id,
            "app_name": app_name,
            "hennge_payload": to_json(payload),
            "status": AgentStatus.SUCCESS.value,
        }

    # -- extraction -----------------------------------------------------------

    def _resolve_id(self, text: str, user_hint: str, fields: "list[tuple[str, str]]") -> str:
        """Explicit id only: text mention > id-shaped hint > 'User id:' field. Never invented."""
        m = _ID_IN_TEXT_RE.search(text)
        if m:
            return m.group(1) or m.group(2) or ""
        hint = user_hint.strip()
        if hint and _ID_SHAPE_RE.match(hint):
            return hint
        for key, value in fields:
            if key.strip().lower() in _ID_KEYS and _ID_SHAPE_RE.match(value.strip()):
                return value.strip()
        return ""  # unresolved - left empty, never invented

    def _resolve_app(self, text: str, fields: "list[tuple[str, str]]") -> str:
        """Extract the target application label, filtered to a renderable alphabet.

        The label is caller-controlled text that renders into the confirmation
        message, so it is reduced to characters a reader cannot act on rather
        than passed through verbatim.
        """
        m = _APP_QUOTED_RE.search(text)
        if m:
            return to_inert_label(m.group(1))
        for key, value in fields:
            if key.strip().lower() in _APP_KEYS:
                return to_inert_label(value)
        return ""

    def _infer_app_name_via_llm(self, text: str, state: dict[str, Any]) -> "str | None":
        """Model-backed app-name extraction; None on ANY failure (never raises).

        Missing/invalid secret, API error, or a malformed/empty response all
        degrade the same way - the caller falls back to the regex/quote
        heuristic, never to a hard node error. Never asked for (and never
        trusted for) user_id - see the module docstring.
        """
        try:
            llm = self._resolve_llm(state)
            response = llm.complete(
                [
                    {"role": "system", "content": _APP_NAME_SYSTEM_PROMPT},
                    {"role": "user", "content": text},
                ]
            )
            parsed = extract_json_object(response.get("content"))
            app_name = parsed.get("app_name")
            if isinstance(app_name, str) and app_name.strip():
                return app_name.strip()
            return None
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

    def _parse_fields(self, text: str) -> "list[tuple[str, str]]":
        """Return the [(key, value), ...] attribute fields parsed from the request lines."""
        fields: list[tuple[str, str]] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            m = _KV_RE.match(stripped)
            if m:
                fields.append((m.group(1).strip(), m.group(2).strip()))
        return fields

    # -- payload assembly (HENNGE One Admin API access-request shape) ----------

    def _build_access_request(self, user_id: str, app_name: str, fields: "list[tuple[str, str]]") -> dict[str, Any]:
        record: dict[str, Any] = {"user_id": user_id}
        if app_name:
            record["app_name"] = app_name
        attributes = []
        for key, value in fields:
            if key.strip().lower() in _ID_KEYS + _APP_KEYS:
                continue
            attributes.append({"name": key, "values": [value]})
        if attributes:
            record["attributes"] = attributes
        return {"access_request": [record]}
