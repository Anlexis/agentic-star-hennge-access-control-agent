# HENNGE Access Control Agent

AI agent for managing access control settings in HENNGE One, built with Agentic Star.

> **Category**: Cat 2 (domain-specific multi-step pipeline)
> **Industry**: Common
> **Template ID**: CMN-C2-282

## Overview

Turns a plain-language access-control request into an action against the
[HENNGE One](https://hennge.com/) Admin REST API: it looks up which applications a user can reach,
grants access, revokes access, or reports the policies assigned to a user, and returns a
confirmation naming the record it touched. Requests arrive as free text ("Look up the app access
status for user id u-1001", "ユーザーID u-1001 のアクセス権を照会してください"), optionally with the
target user supplied alongside them as structured data, and the pipeline validates the request,
classifies the intent, resolves the user and application, assembles the API request body, calls
HENNGE, and formats the confirmation.

Three safety properties are built in rather than bolted on. **Nothing is invented**: the user id
comes only from the caller's structured data or an explicit mention in the request, and an
unresolved id is left empty and reported rather than guessed — so the agent cannot grant or revoke
access on the wrong account. **A vague request never writes**: low-confidence classification falls
back to the read-only lookup. **A blocked response carries nothing**: when the output check
refuses a response, every field that could carry the un-checked answer is cleared, so the refusal
envelope is empty rather than a wrapper around the text that was just rejected.

The target user travels in its own request channel (`input_context`) rather than inside the
request text. That is not a convenience: the framework masks personal data in the text channel at
every step, so an identifier written into the prose can arrive at the API call already rewritten.
The structured channel is validated field by field — an inert character set, bounded length,
and a type check that refuses anything that is not a string — and hostile content is screened on
the raw text, on the sanitized text, and depth-first across the structured payload including its
keys.

The bundled HENNGE transport is a deterministic, network-free stub, so the pipeline runs and tests
end-to-end out of the box without a live HENNGE One tenant. A real deployment injects `get` /
`post` transports at client construction; the request and response shapes already follow the
documented HENNGE One Admin API resource model (users, application access, policies), so no
pipeline change is needed.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Provided by the platform environment, not resolved from the default package index. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent fails at graph
compile / start-up preflight rather than starting in a partially working state. This is intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit and boundary tests
config/       agent manifest (agent.yaml) and runtime settings (config.yaml)
docs/         design and test documentation
```

See `docs/02_design.md` for the node-by-node design and `docs/03_test_spec.md` for the test
specification.

## Customising

1. Adjust `config/config.yaml` for your own HENNGE endpoint and call budget.
2. Inject live `get` / `post` transports into `HenngeClient` and provide `HENNGE_API_TOKEN`
   through the platform secret provider to replace the network-free stub.
3. Review the node implementations under `src/nodes/` for domain-specific logic — the intent
   keywords and the field-extraction patterns are the usual first things to adapt.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
