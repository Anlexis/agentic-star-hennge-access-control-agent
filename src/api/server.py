"""Standalone HTTP entry point for the agent.

Entry points are adapters only - no business logic here. For platform-level
routing, the gateway calls agent.invoke() directly.

The adapter owns three things and nothing else: caller authentication, the
structural caps on the request envelope, and handing the runtime settings from
config/config.yaml to the graph constructor. Field-level validation of caller
data belongs to the domain node that owns the caller contract
(PreProcessNode).
"""

import json
import os
import secrets
from typing import Any, cast
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from shared.secrets import factory as secrets_factory
from src.graph.graph import HENNGEAccessControlAgent, load_runtime_config

app = FastAPI(title="Agent")

# Runtime settings reach the graph HERE. Constructing the agent with no config
# would leave every value declared in config/config.yaml unread.
agent = HENNGEAccessControlAgent(config=load_runtime_config())
agent.compile()
agent.provision_secrets(secrets_factory(namespace="cmn-c2-282", agent_name="HENNGEAccessControlAgent"))

# Structural caps on the request envelope (adapter boundary). Field-level bounds
# are enforced downstream by PreProcessNode; these only stop an oversized or
# absurdly wide body from reaching the graph at all.
_MAX_INPUT_CHARS = 8_000
_MAX_CONTEXT_BYTES = 256 * 1024
_MAX_CONTEXT_ENTRIES = 32


class InvokeRequest(BaseModel):
    input: str
    session_id: str = ""
    # Caller-supplied structured data (target user hint, ...). Forwarded to the
    # graph as the SDK's first-class input_context parameter.
    input_context: dict[str, Any] = Field(default_factory=dict)


def _check_envelope(req: InvokeRequest) -> None:
    """Reject an over-sized request envelope. Names the field, never the value."""
    if len(req.input) > _MAX_INPUT_CHARS:
        raise HTTPException(status_code=413, detail="Field 'input' exceeds the maximum accepted length.")
    if len(req.input_context) > _MAX_CONTEXT_ENTRIES:
        raise HTTPException(status_code=413, detail="Field 'input_context' has too many entries.")
    try:
        encoded = json.dumps(req.input_context, default=str).encode("utf-8")
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Field 'input_context' is not serializable.")
    if len(encoded) > _MAX_CONTEXT_BYTES:
        raise HTTPException(status_code=413, detail="Field 'input_context' exceeds the maximum accepted size.")


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> dict[str, Any]:
    trust = getattr(request.state, "trust_level", TrustLevel.ANONYMOUS)
    # Standalone caller auth: when INVOKE_AUTH_TOKEN is set on the server
    # environment, callers that no upstream middleware vouched for (still
    # ANONYMOUS) must present it as a Bearer token and run at
    # VERIFIED_EXTERNAL. Middleware-established trust is never demoted. This
    # adapter is the entry-point auth boundary - a deployment-level caller
    # credential, not an agent secret, so ctx.secrets does not apply (no
    # InvocationContext exists before auth).
    expected = os.environ.get("INVOKE_AUTH_TOKEN")
    if expected and trust is TrustLevel.ANONYMOUS:
        supplied = request.headers.get("authorization", "")
        # Compare bytes: compare_digest raises TypeError on non-ASCII str input
        # (headers decode as latin-1), which would 500 instead of the generic 401.
        if not secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
            # Generic body on purpose — do not leak whether the token was absent,
            # malformed, or wrong.
            raise HTTPException(status_code=401, detail="Token is invalid or expired.")
        trust = TrustLevel.VERIFIED_EXTERNAL

    _check_envelope(req)

    with bound_secrets(agent._secrets_provider):
        ctx = InvocationContext(
            session_id=req.session_id or str(uuid4()),
            caller_trust_level=trust,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        return cast("dict[str, Any]", agent.invoke(req.input, ctx=ctx, input_context=req.input_context))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "agent": "HENNGEAccessControlAgent"}
