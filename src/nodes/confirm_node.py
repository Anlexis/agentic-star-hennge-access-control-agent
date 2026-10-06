"""Inner workflow Step 5: Confirm.

Formats the looked-up / granted / revoked / policy-checked HENNGE record
(id + reference + target) into a human-readable confirmation message,
surfacing the affected user/app for human review (risk mitigation).
"""

from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

_VERBS = {
    "lookup_access": "Retrieved app access status",
    "grant_access": "Granted app access",
    "revoke_access": "Revoked app access",
    "check_policy": "Retrieved policy assignments",
}


class ConfirmNode(FunctionNode):
    """Build the human-readable confirmation."""

    # Inner domain node, read-only formatting of already-fetched data -
    # the external trust gate lives on the outer backbone pre_process.
    required_trust_level = TrustLevel.ANONYMOUS

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        record_id = state.get("record_id", "")
        record_ref = state.get("record_ref", "")
        user_id = state.get("user_id", "")
        app_name = state.get("app_name", "")
        intent = state.get("intent", "lookup_access")

        if not record_id and not record_ref:
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["ConfirmNode: no record_id/record_ref to confirm"],
            }

        verb = _VERBS.get(intent, "Processed access-control request")
        target = app_name or user_id or record_id
        parts = [f"{verb} '{target}'"]
        if user_id:
            parts.append(f"user={user_id}")
        if record_ref:
            parts.append(f"ref={record_ref}")
        if record_id:
            parts.append(f"id={record_id}")
        confirmation = " - ".join(parts)

        # Audit the confirmed action - intent + reference presence (no content).
        emit_trace_event(
            "confirm_complete",
            {"intent": intent, "has_record_ref": bool(record_ref)},
            state,
        )

        return {
            "confirmation": confirmation,
            "result": {
                "record_id": record_id,
                "record_ref": record_ref,
                "confirmation": confirmation,
            },
            "status": AgentStatus.SUCCESS.value,
        }
