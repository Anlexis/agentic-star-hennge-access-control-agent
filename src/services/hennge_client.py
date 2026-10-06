"""HENNGE One Admin REST API client.

Service layer: a thin wrapper around the HENNGE One (IAM / access-control
SaaS) Admin REST API user-access and policy endpoints. Contains NO business
logic, NO routing, and NO credentials - the integration token is passed in per
call by the node (which reads it via ctx.secrets). This module imports no
framework internals - pure stdlib, which is what keeps the service layer
independently testable.

LIMITATION (deliberate, documented):
    The DEFAULT transport is a deterministic, NETWORK-FREE stub. It returns
    HENNGE One Admin-API-shaped responses (an ``access_data`` list for
    app-access lookups; a ``policy_data`` list for policy checks; the
    task/receipt shape with a synthetic ``grant_id`` / ``revocation_id`` echo
    for grant/revoke, derived from the request) so the pipeline is runnable and
    testable without a live HENNGE One tenant or an HTTP library - it does NOT
    perform a live HENNGE call. The rule it follows: never fake a live call,
    and document the limitation.

    To perform real HENNGE calls, inject live transports (HTTP-library-backed
    ``post`` / ``get``) at construction time; the method contracts follow the
    HENNGE One Admin API resource model (users, application access, policies),
    so going live is a transport injection plus (at most) endpoint-path
    alignment - no business-logic change. A live transport also requires a
    real integration token (see CallHenngeApiNode - the stub runs without one
    because no request ever leaves the process).
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

# A transport callable: (url, headers, json_body, timeout_s) -> (status_code, response_dict).
# A live implementation passes timeout_s straight to its HTTP call so the wait is
# bounded at the socket; the client additionally treats it as a wall-clock budget
# for the whole call (see _call).
Transport = Callable[[str, dict[str, Any], dict[str, Any], float], "tuple[int, dict[str, Any]]"]

_BASE_URL = "https://api.hennge.one/v1"
# Used when the caller constructs the client without a configured budget.
DEFAULT_TIMEOUT_S = 30.0


class HenngeApiError(Exception):
    """Raised when the HENNGE Admin REST API returns a non-2xx status.

    Also raised when a call overruns its configured time budget: an answer that
    arrives late is discarded rather than acted on.
    """

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"HENNGE API error {status_code}: {message}")


class HenngeClient:
    """HENNGE One Admin REST API access-control client.

    Args:
        base_url: HENNGE Admin API base URL (default https://api.hennge.one/v1).
        timeout_s: per-call time budget in seconds. Handed to the transport and
            enforced by this client on the elapsed time of the call.
        post/get: optional injected transports (tests or a live client).
            When none is injected, a deterministic NETWORK-FREE stub is used
            (see the module docstring - it returns the documented shape without
            a live HENNGE call).
    """

    def __init__(
        self,
        base_url: str = _BASE_URL,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        post: Transport | None = None,
        get: Transport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_s = float(timeout_s)
        self._post = post
        self._get = get

    @property
    def timeout_s(self) -> float:
        """The per-call time budget this client was configured with."""
        return self._timeout_s

    # -- transport mode --------------------------------------------------------

    @property
    def uses_stub_transport(self) -> bool:
        """True when NO live transport is injected (the network-free default)."""
        return self._post is None and self._get is None

    # -- auth ----------------------------------------------------------------

    def _headers(self, api_token: str) -> dict[str, str]:
        """Build the HENNGE Admin REST API auth headers.

        api_token is supplied per-call by the node (from ctx.secrets); it is
        never persisted on the instance or logged.
        """
        return {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_token,
        }

    # -- deterministic stub transport (default; NO network) -------------------

    def _stub_transport(
        self, url: str, headers: dict[str, Any], json_body: dict[str, Any], timeout_s: float
    ) -> tuple[int, dict[str, Any]]:
        """Deterministic, network-free stub - returns the documented HENNGE shape.

        NOT a live call, so ``timeout_s`` has nothing to bound here; it is part
        of the transport contract a live implementation honours. Synthetic ids
        are derived from the request so the response is stable and inspectable.
        See the module docstring for the limitation and how to inject live
        transports.
        """
        _ = timeout_s
        seed = url + "|" + json.dumps(json_body, sort_keys=True, ensure_ascii=False, default=str)
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        op = json_body.get("_hennge_op")
        user_id = str(json_body.get("user_id", "")) or f"u-{digest[:8]}"
        if op == "lookup":
            # Admin-API-shaped GET /users/{id}/applications response.
            return 200, {
                "user_id": user_id,
                "access_data": [
                    {
                        "app_id": f"app-{digest[:6]}",
                        "app_name": f"app-{digest[:6]}",
                        "status": "active",
                    }
                ],
                "_stub": True,  # marks the network-free stub response
            }
        if op == "policies":
            # Admin-API-shaped GET /users/{id}/policies response.
            return 200, {
                "user_id": user_id,
                "policy_data": [
                    {
                        "policy_id": f"pol-{digest[:6]}",
                        "policy_name": f"policy-{digest[:6]}",
                        "status": "assigned",
                    }
                ],
                "_stub": True,  # marks the network-free stub response
            }
        # POST /access-grants (grant) / POST /access-revocations (revoke) -
        # task-receipt shape, plus a synthetic grant/revocation id echo so the
        # caller can reference the affected record without a follow-up lookup.
        request = json_body.get("access_request") or [{}]
        first = request[0] if isinstance(request, list) and request else {}
        target = str(first.get("user_id", "")) or user_id
        receipt: dict[str, Any] = {
            "task_id": int(digest[:6], 16),
            "user_id": target,
            "_stub": True,  # marks the network-free stub response
        }
        if url.endswith("/access-revocations"):
            receipt["revocation_id"] = f"r-{digest[:8]}"
        else:
            receipt["grant_id"] = f"g-{digest[:8]}"
        return 200, receipt

    def _resolve(self, injected: Transport | None) -> Transport:
        return injected or self._stub_transport

    def _call(
        self, transport: Transport, url: str, headers: dict[str, Any], body: dict[str, Any]
    ) -> "tuple[int, dict[str, Any]]":
        """Run one transport call under the configured time budget.

        The budget is passed to the transport (a live one bounds its own socket
        wait with it) and re-checked here on elapsed time, so an overrun is an
        error rather than a late answer the pipeline treats as authoritative.
        """
        started = time.monotonic()
        status, body_out = transport(url, headers, body, self._timeout_s)
        elapsed = time.monotonic() - started
        if elapsed > self._timeout_s:
            raise HenngeApiError(
                504,
                f"call exceeded the configured {self._timeout_s}s budget",
            )
        return status, body_out

    # -- public API ---------------------------------------------------------

    def get_user_access(self, user_id: str, api_token: str) -> dict[str, Any]:
        """GET /users/{id}/applications - look up a user's app-access status.

        Returns the parsed response dict (containing ``access_data``). Raises
        HenngeApiError on non-2xx.
        """
        url = f"{self._base_url}/users/{user_id}/applications"
        transport = self._resolve(self._get)
        status, body = self._call(
            transport, url, self._headers(api_token), {"_hennge_op": "lookup", "user_id": user_id}
        )
        if not (200 <= status < 300):
            raise HenngeApiError(status, _err_message(body))
        return body

    def get_user_policies(self, user_id: str, api_token: str) -> dict[str, Any]:
        """GET /users/{id}/policies - look up a user's policy assignments.

        Returns the parsed response dict (containing ``policy_data``). Raises
        HenngeApiError on non-2xx.
        """
        url = f"{self._base_url}/users/{user_id}/policies"
        transport = self._resolve(self._get)
        status, body = self._call(
            transport, url, self._headers(api_token), {"_hennge_op": "policies", "user_id": user_id}
        )
        if not (200 <= status < 300):
            raise HenngeApiError(status, _err_message(body))
        return body

    def grant_access(self, payload: dict[str, Any], api_token: str) -> dict[str, Any]:
        """POST /access-grants - grant a user access to an application.

        ``payload`` is the ``{"access_request": [...]}`` request body. Returns
        the parsed response dict (task receipt with ``grant_id``). Raises
        HenngeApiError on a non-2xx status.
        """
        url = f"{self._base_url}/access-grants"
        transport = self._resolve(self._post)
        status, body = self._call(transport, url, self._headers(api_token), payload)
        if not (200 <= status < 300):
            raise HenngeApiError(status, _err_message(body))
        return body

    def revoke_access(self, payload: dict[str, Any], api_token: str) -> dict[str, Any]:
        """POST /access-revocations - revoke a user's access to an application.

        ``payload`` is the ``{"access_request": [...]}`` request body. Returns
        the parsed response dict (task receipt with ``revocation_id``). Raises
        HenngeApiError on a non-2xx status.
        """
        url = f"{self._base_url}/access-revocations"
        transport = self._resolve(self._post)
        status, body = self._call(transport, url, self._headers(api_token), payload)
        if not (200 <= status < 300):
            raise HenngeApiError(status, _err_message(body))
        return body


def _err_message(body: Any) -> str:
    """Extract a human-readable error message from a HENNGE error body."""
    if isinstance(body, dict):
        errors = body.get("errors")
        if isinstance(errors, list) and errors:
            return "; ".join(str(e) for e in errors)
        msg = body.get("message")
        if msg:
            return str(msg)
    return str(body)
