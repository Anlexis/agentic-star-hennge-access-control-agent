"""AGENTIC STAR Marketplace entrypoint — one-shot Pod process.

Referenced by this repo's Dockerfile as the image `CMD`. Compiles the agent,
provisions its secrets, then hands off to shared.bootstrap.marketplace_app
for the Marketplace lifecycle (identity, input, events, terminal delivery,
exit). Mirrors agentcore's own `agents/base/chat_agent/cli.py` (the pattern
this file was copied from).

`namespace=` here is the Marketplace secret-provisioning namespace. It mirrors
`src/api/server.py`'s existing `secrets_factory(namespace="cmn-c2-282", ...)`
call — this template scopes secrets per-template (not per-industry), matching
its already-deployed production identity.
"""

from pathlib import Path

from shared.bootstrap.marketplace_app import run_agent_marketplace
from src.graph.graph import HENNGEAccessControlAgent, load_runtime_config

if __name__ == "__main__":
    run_agent_marketplace(
        HENNGEAccessControlAgent,
        agent_name="HENNGEAccessControlAgent",
        namespace="cmn-c2-282",
        config=load_runtime_config(),
    )
