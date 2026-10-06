"""Outer pre_process node - the caller-contract boundary.

Cat 2 outer backbone: validate the caller's request (raw natural-language text
plus the structured target hint supplied as ``input_context``) and serialize it
into a single JSON string in ``validated_input``, which the GraphNode (`main`
slot) hands to the inner HENNGE workflow graph.

This node owns the caller contract, so refusal happens HERE rather than being
delegated upstream: the framework's own input gate blocks only high-confidence
findings on ``user_input``/``validated_input`` and does not see
``input_context`` at all, so a template that relies on it alone returns SUCCESS
on payloads it should have refused. Screening runs on the raw text (control
tokens are visible before markup stripping removes them), on the sanitized text
(directives split apart by markup are visible once it is re-assembled), and
depth-first over the parsed context including its keys.

Business validation of the request itself happens inside the inner graph's
ValidateInputNode; this node does the caller-data contract and the shaping.
"""

import json
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services.security import (
    sanitize_query,
    screen_raw_and_sanitized,
    validate_caller_context,
)


class PreProcessNode(FunctionNode):
    """Validate and serialize caller input for the inner workflow graph."""

    # The outer backbone's SINGLE external trust gate. A real caller enters at
    # VERIFIED_EXTERNAL and the inner HENNGE call runs under this same
    # (unelevated) context, so the external gate lives HERE, not on the inner
    # API node. An under-trusted (ANONYMOUS) caller is denied at this gate
    # before any call.
    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        user_input = state.get("user_input", "")
        input_context = state.get("input_context", {})  # read-only

        if not isinstance(user_input, str) or not user_input.strip():
            return self._refuse("user_input is empty or missing", state)

        raw = user_input.strip()
        # Strip markup and zero-width characters, cap length. Sanitizing only -
        # the refusal decision is the screen below, over both representations.
        sanitized_input = sanitize_query(raw)

        reason = screen_raw_and_sanitized(raw, sanitized_input)
        if reason:
            return self._refuse(f"request rejected: {reason}", state)

        # Target user is caller-supplied and never inferred here. A present but
        # malformed field is refused, not silently dropped.
        user_hint, context_error = validate_caller_context(input_context)
        if context_error:
            return self._refuse(context_error, state)

        validated_input = json.dumps({"text": sanitized_input, "user_hint": user_hint})

        # Audit the shaped request - hint presence only, never the raw text.
        emit_trace_event(
            "pre_process_complete",
            {"has_user_hint": bool(user_hint)},
            state,
        )

        return {
            "validated_input": validated_input,
            "user_hint": user_hint,
            "status": AgentStatus.SUCCESS.value,
        }

    def _refuse(self, message: str, state: dict[str, Any]) -> dict[str, Any]:
        """Refuse the request: error status, a field-naming reason, nothing carried forward.

        The message names the field or the finding class - never the rejected
        value, which is caller-controlled text.
        """
        emit_trace_event(
            "pre_process_refused",
            {"reason": message},
            state,
        )
        return {
            "status": AgentStatus.ERROR.value,
            "error_log": [f"PreProcessNode: {message}"],
            "validated_input": "",
            "user_hint": "",
        }
