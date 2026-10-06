"""Outer post_process node - the output boundary.

Cat 2 outer backbone: finalize the response after the inner HENNGE workflow
graph has run. GraphNode.merge_output() maps the inner result into the outer
state; this node shapes the caller-facing `formatted_output`.

The domain output gate is the MODULE-LEVEL `_security_gate_output()` below,
called from execute(). It is deliberately NOT an instance method and NOT the
framework's `_extra_security_gate_output` hook - the framework gate methods are
@final on FunctionNode and the SDK auto-wraps `_extra_` hooks, which breaks the
invocation chain, so domain checks live in a module-level helper invoked inline.

Three properties this node exists to hold:

* **A gate that only raises is not containment.** ``AgentBaseGraph.get_output``
  falls back to ``state["result"]`` whenever ``formatted_output`` is empty -
  even when the status is ERROR. An error return that does not clear the
  output-bearing fields therefore still ships the un-gated inner answer inside
  the error envelope. EVERY non-success return here - the gate violation AND
  the pre-existing inner-workflow failure - goes through the one module-level
  ``_contain()`` helper, which clears every field that can carry released text
  and replaces ``formatted_output`` with a TRUTHY mapping so the ``or result``
  fallback never fires.
* **The caller-visible error is a closed set.** On a non-success path
  ``formatted_output`` is exactly ``{"reason": <code>}`` with the code drawn
  from ``ERROR_REASONS`` - never ``error_log``, never the gate's violation
  entries, never any other node-authored text. Those lines can embed an
  upstream API error body, identifiers, names or caller-derived fragments, and
  truncating, path-stripping or credential-only redaction of them is not a
  closed set. ``error_log`` stays the INTERNAL channel: the state reducer
  appends to it and the audit trail needs it; it is simply never projected to
  the caller. Gate violations are written there naming the offending PATH
  (fixed keys and indices, never the value), and the audit event carries a
  count.
* **No error envelope carries HENNGE record evidence.** ``record_id`` /
  ``record_ref`` are this agent's WRITE EVIDENCE - ``_security_gate_output()``
  below REFUSES a SUCCESS that lacks them - so returning them under an ERROR
  status would tell a caller being informed of failure that an access record
  was nonetheless touched, and which one. HENNGE One is an identity/access
  system: the user id, the application name and the grant/revocation
  references are personal data and the audit trail of a privileged write.
  ``_contain()`` reads nothing out of state - not the record, not the log.
"""

import re
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json

# Credential-shaped strings that must never reach the caller (defence in depth -
# the framework's own output credential scan also runs on every result).
_CREDENTIAL_LIKE_RE = re.compile(r"eyJ[A-Za-z0-9._-]{10,}|sk-[A-Za-z0-9]{20,}|Bearer\s+[A-Za-z0-9._-]{16,}")

# Stand-in for a mapping key that cannot itself be written into a path label.
_UNNAMEABLE_KEY = "<withheld>"

# Every state field that can carry text produced by the inner workflow. Cleared
# as a set on EVERY non-success return, so nothing survives into the error
# envelope - and nothing survives in state either, where a checkpoint or a
# downstream reader would pick it straight back up. Omitting a field from one
# envelope is not clearing it.
_OUTPUT_BEARING_FIELDS = (
    "result",
    "formatted_output",
    "confirmation",
    "record_id",
    "record_ref",
    "user_id",
    "app_name",
    "intent",
    "hennge_payload",
    "redaction_flags",
)

# Reason codes - the ONLY values the caller-visible ERROR envelope may carry.
# Chosen here, never derived from state, so the envelope is a closed set: it
# says WHAT happened, never to which HENNGE record and never in whose words.
_REASON_WORKFLOW_FAILED = "hennge_workflow_failed"  # the inner workflow reported an error
_REASON_OUTPUT_WITHHELD = "output_withheld_by_gate"  # the output gate refused the response
ERROR_REASONS = frozenset({_REASON_WORKFLOW_FAILED, _REASON_OUTPUT_WITHHELD})


def _cleared_output_state() -> dict[str, Any]:
    """Blank every output-bearing field. _contain() overwrites formatted_output."""
    return {field: "" for field in _OUTPUT_BEARING_FIELDS}


def _contain(reason: str, new_errors: list[str] | None = None) -> dict[str, Any]:
    """The node result for ANY non-success outcome - the single error shape.

    Error status, every output-bearing field cleared (_cleared_output_state),
    and an envelope made of closed-set labels only: ``reason`` is one of
    ERROR_REASONS. ``new_errors`` (this node's own gate violations - path
    labels only) are appended to ``error_log``, the internal channel the state
    reducer accumulates, and never enter the envelope. Nothing is read out of
    state: not the record, not ``error_log`` - the inner entries are already
    there, and re-emitting them would duplicate every line.

    The constant ``reason`` key keeps the mapping TRUTHY, so the framework's
    ``formatted_output or result`` projection (AgentBaseGraph.get_output()
    applies no status check) serves this envelope and never whatever survived
    in ``result``.
    """
    contained: dict[str, Any] = _cleared_output_state()
    contained["formatted_output"] = {"reason": reason}
    contained["status"] = AgentStatus.ERROR.value
    if new_errors:
        contained["error_log"] = list(new_errors)
    return contained


def _join(path: str, label: str) -> str:
    return f"{path}.{label}" if path else label


def _credential_findings(value: object, path: str) -> list[str]:
    """Walk a nested structure and report every credential-shaped string - leaf
    values AND mapping keys.

    Scanning only the top level would miss a token riding inside a nested
    mapping such as the assembled request body, which is exactly where one is
    most likely to appear. A finding names the offending PATH, never the value.

    A credential-shaped KEY is a finding too, and it is withheld from the path
    label rather than quoted into it: the label travels in ``error_log``, where
    the framework's own credential scan would raise on this node's result and
    replace the cleared fields around it with a bare error - restoring the very
    ``result`` fallback the clearing closed.
    """
    problems: list[str] = []
    if isinstance(value, str):
        if _CREDENTIAL_LIKE_RE.search(value):
            problems.append(f"output gate: credential-like value in formatted_output[{path}]")
        return problems
    if isinstance(value, dict):
        for key, item in value.items():
            label = str(key)
            if isinstance(key, str) and _CREDENTIAL_LIKE_RE.search(key):
                label = _UNNAMEABLE_KEY
                problems.append(f"output gate: credential-like mapping key in formatted_output[{_join(path, label)}]")
            problems.extend(_credential_findings(item, _join(path, label)))
        return problems
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            problems.extend(_credential_findings(item, f"{path}[{index}]"))
        return problems
    return problems


def _security_gate_output(formatted_output: dict[str, Any], is_success: bool) -> list[str]:
    """Domain output gate (module-level; called from PostProcessNode.execute()).

    Blocks (returns violations for):
      - a SUCCESS response with no record evidence (record_id/record_ref), which
        would misrepresent the HENNGE action outcome to the caller;
      - any credential-shaped string anywhere in the caller-facing output -
        nested values, list entries and mapping keys included.

    A violation names the offending PATH, never the value. Violations are
    ``error_log`` entries (internal); they never reach the caller.
    """
    problems: list[str] = []
    if is_success and not (formatted_output.get("record_id") or formatted_output.get("record_ref")):
        problems.append("output gate: SUCCESS output missing record_id/record_ref evidence")
    problems.extend(_credential_findings(formatted_output, ""))
    return problems


class PostProcessNode(FunctionNode):
    """Format the final agent output."""

    # Read-only formatting of the already-produced result.
    required_trust_level = TrustLevel.ANONYMOUS

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # If the inner workflow errored, preserve the error status (do not mask
        # it) and publish NOTHING of it: error_log already carries the inner
        # entries (the state reducer appends, so re-emitting them here would
        # duplicate every line), and the caller receives the reason code only.
        # The delta clears every output-bearing field, so the identifiers and
        # the application label cannot be recovered from the checkpoint or by
        # a downstream reader either.
        if state.get("status") == AgentStatus.ERROR.value:
            # Outcome signals only - a closed-set reason code and a count. The
            # audit log is not a store for access-record content or error text.
            emit_trace_event(
                "post_process_error_contained",
                {"reason": _REASON_WORKFLOW_FAILED, "error_count": len(state.get("error_log") or [])},
                state,
            )
            return _contain(_REASON_WORKFLOW_FAILED)

        formatted_output = {
            "record_id": state.get("record_id", ""),
            "record_ref": state.get("record_ref", ""),
            "user_id": state.get("user_id", ""),
            "app_name": state.get("app_name", ""),
            "intent": state.get("intent", ""),
            "confirmation": state.get("confirmation", ""),
            "hennge_payload": from_json(state.get("hennge_payload"), {}),
        }

        # Domain output gate (module-level helper - see module docstring). A
        # refusal is contained the same way as an inner error: the violations
        # go to error_log only, the caller receives the reason code only.
        violations = _security_gate_output(formatted_output, is_success=True)
        if violations:
            emit_trace_event(
                "post_process_output_blocked",
                {"reason": _REASON_OUTPUT_WITHHELD, "violation_count": len(violations)},
                state,
            )
            return _contain(_REASON_OUTPUT_WITHHELD, violations)

        # Audit the final response shaping - outcome signals only, no content.
        emit_trace_event(
            "post_process_complete",
            {
                "intent": state.get("intent", ""),
                "has_record_id": bool(state.get("record_id")),
            },
            state,
        )

        return {
            "formatted_output": formatted_output,
            "status": AgentStatus.SUCCESS.value,
        }
