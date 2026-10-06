"""HENNGE Access Control Agent state."""

# State must be a flat TypedDict - never a Pydantic BaseModel. Checkpoints are
# msgpack-serialized; Pydantic objects (and nested dict/list containers) are
# not msgpack-safe. Extend AgentState with agent-specific fields only, and
# declare every domain field NotRequired[...] (fields are absent until their
# producer node writes them). hennge_payload / hennge_config / redaction_flags
# are dicts/lists at the point of use but are stored in State as JSON strings
# via to_json/from_json below. Do NOT add credentials, secrets, or Pydantic
# models. The HENNGE integration token is NEVER stored here - it is read via
# ctx.secrets in CallHenngeApiNode.

from __future__ import annotations

import json
from typing import Any, NotRequired, Optional

from framework.schemas.agent_state import AgentState


def to_json(value: Any) -> Optional[str]:
    """Serialize a list/dict State value to a compact JSON string (msgpack-safe).

    Returns None for None so the field stays a true Optional[str].
    """
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def from_json(value: Any, default: Any) -> Any:
    """Deserialize a JSON-string State value back to its list/dict form.

    Tolerant by design: None/empty -> default; an already-native list/dict (e.g. a value
    supplied directly in a unit test) passes through unchanged; a malformed string -> default.
    """
    if value is None or value == "":
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class State(AgentState):
    """HENNGE access-control agent state.

    Shared fields (user_input, validated_input, intent, result, status,
    formatted_output, session_id, node_history, error_log, correlation_id,
    trace_id, hitl_*, etc.) are inherited from AgentState and NOT re-declared.
    Only HENNGE-workflow fields are added below, all NotRequired (the state
    contract). All values are JSON/msgpack-serializable primitives -
    the HENNGE integration token is NEVER stored here (accessed via
    ctx.secrets).
    """

    # Caller-supplied target hint (HENNGE user id from input_context / the
    # request envelope). Never inferred; resolution to a HENNGE user id is
    # explicit-only (v1: pass-through when the hint or request text already
    # carries an id like u-1001).
    user_hint: NotRequired[str]
    user_id: NotRequired[str]  # resolved HENNGE user id

    # ValidateInput (deterministic redaction scan)
    # JSON list[str] of patterns redacted from the text before logging
    # (stored as a JSON string; (de)serialize via to_json/from_json).
    redaction_flags: NotRequired[Optional[str]]

    # InferHenngeFields
    app_name: NotRequired[str]  # target application label (grant/revoke target)
    # JSON - assembled HENNGE One Admin REST API request body (stored as a
    # JSON string, not a native dict; (de)serialize via to_json/from_json).
    hennge_payload: NotRequired[Optional[str]]

    # The `hennge:` settings from config/config.yaml, forwarded by
    # _parent_config() and injected by the inner graph's
    # _extra_initial_state() (JSON string).
    hennge_config: NotRequired[Optional[str]]

    # CallHenngeApi
    record_id: NotRequired[str]  # user id / grant id / revocation id returned by HENNGE
    record_ref: NotRequired[str]  # human-readable reference (hennge://users/<id>/applications, ...)

    # Confirm
    confirmation: NotRequired[str]  # human-readable confirmation message
