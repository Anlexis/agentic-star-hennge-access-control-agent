"""Inner workflow Step 4: CallHenngeApi (tool side-effect).

Performs the lookup/grant/revoke/policy-check call against the HENNGE One
Admin REST API access-control endpoints via src/services/hennge_client.py.

Security posture:
  Trust: required_trust_level = ANONYMOUS. The single external trust gate lives
       on the OUTER backbone pre_process (VERIFIED_EXTERNAL), not on this inner
       node. GraphNode.execute() passes the caller's InvocationContext into the
       inner subgraph UNCHANGED (no trust elevation), so a real external caller
       runs this call under its own VERIFIED_EXTERNAL context; declaring
       INTERNAL here would deny that already-gated external caller before the
       call ever runs. The node therefore stays ANONYMOUS.
  Credentials: the integration token is read via
       ctx.secrets.get("HENNGE_API_TOKEN") (InvocationContext.from_state(state))
       - never os.environ, never stored in state. The token is OPTIONAL rather
       than required: the default transport is the deterministic NETWORK-FREE
       stub, and a missing token is tolerated there (a sentinel placeholder is
       used - it is never sent anywhere because no request leaves the process).
       With a LIVE transport injected, a missing token is a hard status=error -
       a real API is never called unauthenticated.
  Audit: emit_trace_event() is called on the success path - a side-effect
       against an external identity system; HTTP 4xx/5xx surfaces as
       status=error + error_log (no silent pass).

Configuration: this node takes NO constructor arguments (SDK v1 nodes are
no-arg). HENNGE settings (base_url, timeout_s) arrive as the JSON
`hennge_config` state field - injected by the inner graph's
_extra_initial_state() from the section forwarded by
HenngeWorkflowGraphNode._parent_config(), which reads config/config.yaml - or
via the optional `config["configurable"]["hennge"]` argument for direct
invocation. The client is constructed locally per call (no module-global
mutation).
"""

from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json
from src.services.hennge_client import DEFAULT_TIMEOUT_S, HenngeApiError, HenngeClient
from src.services.security import finite_in_range

_SECRET_KEY = "HENNGE_API_TOKEN"
# Placeholder handed to the network-free stub transport when no secret is
# provisioned. Never sent over any network (the stub performs no I/O) and never
# written to state or logs.
_STUB_PLACEHOLDER = "stub-transport-no-credential"


class CallHenngeApiNode(FunctionNode):
    """Look up / grant / revoke app access or check policies via the HENNGE Admin API."""

    # The external trust gate is enforced UPSTREAM on the outer backbone
    # pre_process (VERIFIED_EXTERNAL). This inner node runs under the caller's
    # UNELEVATED context (GraphNode does not elevate trust for the subgraph), so
    # it must stay ANONYMOUS - declaring INTERNAL would deny a real external
    # caller before the call runs.
    required_trust_level = TrustLevel.ANONYMOUS

    def execute(self, state: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = from_json(state.get("hennge_payload"), None)
        if not payload:
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["CallHenngeApiNode: missing hennge_payload"],
            }

        intent = state.get("intent", "lookup_access") or "lookup_access"

        # Settings: manifest section from state (graph-injected), overridable via
        # an explicit config["configurable"]["hennge"] for direct invocation.
        # Merged into a LOCAL dict - module globals are never mutated.
        settings = dict(from_json(state.get("hennge_config"), {}) or {})
        override = ((config or {}).get("configurable") or {}).get("hennge") or {}
        settings.update(override)

        # The declared time budget is parsed fail-CLOSED: NaN and +-Infinity
        # survive float() and then compare False against every bound, which
        # would leave the call effectively unbounded.
        timeout_s = DEFAULT_TIMEOUT_S
        if "timeout_s" in settings:
            parsed, timeout_error = finite_in_range(
                settings["timeout_s"], field="hennge.timeout_s", minimum=0.0, maximum=600.0
            )
            if timeout_error:
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": [f"CallHenngeApiNode: {timeout_error}"],
                }
            timeout_s = float(parsed or 0.0)

        # Client built locally per call; with no injected transport it uses the
        # deterministic NETWORK-FREE stub (documented limitation, see the design
        # notes).
        base_url = str(settings.get("base_url", "") or "").strip()
        client = HenngeClient(base_url=base_url, timeout_s=timeout_s) if base_url else HenngeClient(timeout_s=timeout_s)

        # Token from the bound secret provider - never os.environ / state.
        ctx = InvocationContext.from_state(state)
        api_token = ctx.secrets.get(_SECRET_KEY)
        if api_token is None:
            if client.uses_stub_transport:
                # Stub limitation: no request leaves the process, so run with
                # a non-credential placeholder (see module docstring).
                api_token = _STUB_PLACEHOLDER
            else:
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": [
                        f"CallHenngeApiNode: secret {_SECRET_KEY} unavailable - "
                        "refusing to call a live transport unauthenticated"
                    ],
                }

        user_id = state.get("user_id", "") or str(payload.get("user_id", "") or "")
        app_name = state.get("app_name", "")

        if not user_id:
            # Every intent targets a specific user account; an unresolved id is
            # never invented (design decision record, "Write target").
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"CallHenngeApiNode: unresolved user id - cannot {intent.replace('_', ' ')}"],
            }

        try:
            if intent == "lookup_access":
                resp = client.get_user_access(user_id, api_token) or {}
                entries = resp.get("access_data") or []
                if not entries:
                    # The reason names the INTENT (a closed-set label), never the
                    # account: error_log rides the caller-facing error envelope,
                    # so interpolating the user id would put the record evidence
                    # straight back into it by another key.
                    return {
                        "status": AgentStatus.ERROR.value,
                        "error_log": ["CallHenngeApiNode: no access records found for the requested user"],
                    }
                record_id = user_id
                record_ref = f"hennge://users/{user_id}/applications"
                app_name = app_name or str(entries[0].get("app_name", ""))
            elif intent == "check_policy":
                resp = client.get_user_policies(user_id, api_token) or {}
                policies = resp.get("policy_data") or []
                if not policies:
                    # Closed-set label only - see the lookup branch above.
                    return {
                        "status": AgentStatus.ERROR.value,
                        "error_log": ["CallHenngeApiNode: no policy assignments found for the requested user"],
                    }
                record_id = user_id
                record_ref = f"hennge://users/{user_id}/policies"
            elif intent == "grant_access":
                resp = client.grant_access(payload, api_token) or {}
                record_id = str(resp.get("grant_id", "")) or user_id
                record_ref = f"hennge://access-grants/{record_id}"
            elif intent == "revoke_access":
                resp = client.revoke_access(payload, api_token) or {}
                record_id = str(resp.get("revocation_id", "")) or user_id
                record_ref = f"hennge://access-revocations/{record_id}"
            else:
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": [f"CallHenngeApiNode: unknown intent '{intent}'"],
                }
        except HenngeApiError as exc:
            # HTTP status only. HenngeApiError stringifies the upstream error
            # BODY (_err_message()), which on a live tenant is unbounded
            # third-party text that can echo the account and application it
            # refused - and this reason ships in the caller-facing error
            # envelope. The closed-set signal travels; the body does not.
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"CallHenngeApiNode: HENNGE API error {exc.status_code}"],
            }
        except Exception as exc:  # transport failure - no silent pass
            # Exception TYPE only, for the same reason: a transport error string
            # carries the request URL, which embeds the user id.
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"CallHenngeApiNode: HENNGE call failed ({type(exc).__name__})"],
            }

        # Audit the tool side-effect - intent + presence signals only,
        # never user/app content or credentials.
        emit_trace_event(
            "call_hennge_api_complete",
            {
                "intent": intent,
                "has_record_id": bool(record_id),
                "stub_transport": client.uses_stub_transport,
            },
            state,
        )

        return {
            "record_id": record_id,
            "record_ref": record_ref,
            "user_id": user_id,
            "app_name": app_name,
            "status": AgentStatus.SUCCESS.value,
        }
