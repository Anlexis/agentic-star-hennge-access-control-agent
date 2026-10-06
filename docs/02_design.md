# Template Design Specification — CMN-C2-282 HENNGE Access Control Agent

## Position in the framework architecture

| Item | Value |
|------|-------|
| Agent class | `HENNGEAccessControlAgent` (`src/graph/graph.py`) |
| L1 Base (framework base class) | `AgentBaseGraph` — direct framework inheritance |
| Category | Cat 2 (multi-step domain workflow, tool-calling) |
| Base type | ToolCallingAgent |
| Composition | outer 5-node backbone; the domain pipeline is encapsulated in a `GraphNode` (`main` slot) wrapping an inner `BaseGraph` (`src/graph/domain_workflow_graph.py`) |
| Pipeline shape | classify intent → extract the access-control fields → build a HENNGE One Admin REST API request → call the tool → format the confirmation. No retrieval, no autonomous loop. |

**Three-layer separation:**
- State: flat TypedDict `State(AgentState)` (no Pydantic — not serializable for checkpoints)
- Node: framework inheritance (Template Method: `execute(self, state) -> dict` override only)
- Graph: composition (`register_nodes()` + `super().register_nodes()`; `add_edges()`
  not overridden on the outer graph)

## Architecture Overview

### Outer graph — node configuration (`src/graph/graph.py`)

| Node | Responsibility | Input State | Output State | Trust | Inherits/Overrides |
|------|---------------|-------------|--------------|-------|-------------------|
| initialize | framework setup (schema, session, trust) | user_input | session/trust fields | framework default | InitializeNode (default) |
| pre_process | the caller-data contract: screen the request, validate `input_context`, sanitize and serialize `{"text", "user_hint"}` into `validated_input` (JSON) | user_input, input_context | validated_input, user_hint | **VERIFIED_EXTERNAL** (the single external gate) | PreProcessNode (FunctionNode) |
| main | run the inner HENNGE workflow subgraph | validated_input | result, intent, user_id, record_id, record_ref, app_name, confirmation, hennge_payload | GraphNode (caller ctx forwarded unchanged) | HenngeWorkflowGraphNode (GraphNode) |
| post_process | the output boundary: shape `formatted_output`, run the module-level `_security_gate_output()` scan, and CLEAR every output-bearing field on a violation | inner-result fields | formatted_output | ANONYMOUS | PostProcessNode (FunctionNode) |
| finalize | framework finalize (metadata, timing) | — | response_metadata | framework default | FinalizeNode (default) |

### Inner workflow — node configuration (`src/graph/domain_workflow_graph.py`)

Inner graph inherits `BaseGraph` (fully custom linear topology). The 5 pipeline
steps map 1:1 to inner nodes. **Every inner domain node declares
`required_trust_level = TrustLevel.ANONYMOUS`** — the caller's
`InvocationContext` is forwarded into the subgraph unchanged, so the single
external trust gate stays on the backbone `pre_process`.

| Inner node | Step | Responsibility | Output | Trust |
|------|------|---------------|--------|-------------|
| validate_input | 1 ValidateInput | empty/non-request guard; deterministic (regex) flag-and-redact of email/token-like strings before logging | validated_input, user_hint, redaction_flags | ANONYMOUS |
| classify_intent | 2 ClassifyIntent | deterministic keyword classification -> lookup_access / grant_access / revoke_access / check_policy; low-confidence -> lookup_access (read-only default — never a write) | intent | ANONYMOUS |
| infer_hennge_fields | 3 InferHenngeFields | extract user id / target app name / "Key: value" attribute fields (the app label is filtered to a renderable alphabet before it can reach the output); assemble the HENNGE One Admin REST API request body per intent; an unresolved user id is left empty (never invented) | user_id, app_name, hennge_payload | ANONYMOUS |
| call_hennge_api | 4 CallHenngeApi | GET /users/{id}/applications (lookup) / GET /users/{id}/policies (policy check) / POST /access-grants (grant) / POST /access-revocations (revoke) via `HenngeClient`; token via ctx.secrets; the declared call budget is parsed finite+bounded and enforced; 4xx/5xx or an overrun -> status=error | record_id, record_ref, user_id, app_name | ANONYMOUS |
| confirm | 5 Confirm | format intent + record id + reference into a human-readable confirmation | confirmation, result | ANONYMOUS |

### Data Flow

```
Outer:  START -> initialize -> pre_process -> main -> {route} -> post_process -> finalize -> END
                                              | (RETRY, max 3) ^
Inner (inside main / HenngeWorkflowGraphNode):
        START -> validate_input -> classify_intent -> infer_hennge_fields
              -> call_hennge_api -> confirm -> END
```

Structured parameters travel as a JSON string: `pre_process` serializes
`{"text", "user_hint"}` into `validated_input`,
`HenngeWorkflowGraphNode.extract_input()` hands that JSON to the subgraph, and
the first inner node (`validate_input`) parses it back. Inner nodes read
`state.get("validated_input") or state.get("user_input", "")`.

### State Definition (`src/schemas/state.py`)

All domain fields are declared `NotRequired[...]` (the state contract —
fields are absent until their producer node writes them). Dict/list payloads
are stored as JSON strings (`Optional[str]`) via the module helpers
`to_json` / `from_json`, used by every producer and consumer.

| Field | Type | Purpose | Producer |
|-------|------|---------|----------|
| user_hint | NotRequired[str] | caller-supplied HENNGE user id hint; never inferred | pre_process / validate_input |
| user_id | NotRequired[str] | resolved HENNGE user id (pass-through when the hint/text already carries an id like `u-1001`) | infer_hennge_fields |
| redaction_flags | NotRequired[Optional[str]] | JSON list of patterns redacted before logging | validate_input |
| app_name | NotRequired[str] | target application label (grant/revoke target) | infer_hennge_fields / call_hennge_api |
| hennge_payload | NotRequired[Optional[str]] | JSON — assembled HENNGE One Admin REST API request body (checkpoint-safe: stored as a JSON string via `to_json`/`from_json`) | infer_hennge_fields |
| hennge_config | NotRequired[Optional[str]] | JSON — the `hennge:` settings from `config/config.yaml`, forwarded by `_parent_config()` and injected via the inner graph's `_extra_initial_state()` | inner graph |
| record_id | NotRequired[str] | user id / grant id / revocation id returned by HENNGE | call_hennge_api |
| record_ref | NotRequired[str] | human-readable record reference (`hennge://users/<id>/applications`, `hennge://access-grants/<id>`, ...) | call_hennge_api |
| confirmation | NotRequired[str] | human-readable confirmation | confirm |

`intent`, `result`, `validated_input`, `formatted_output` are inherited from
`AgentState` and are **not** re-declared.

**State Constraints (mandatory, satisfied):**
- Flat TypedDict only (primitives + JSON-serializable) — no Pydantic/dataclass.
- No JWT / API keys / credentials in State — the HENNGE token is accessed via `ctx.secrets`.
- InvocationContext read via `InvocationContext.from_state(state)`, never stored in State.

## Configuration and the caller-data contract

### Where settings live

`config/agent.yaml` is the FLAT registry manifest: identity, entry point, entry
trust level, and the compile-time `requires` block, all at root level. It holds
no runtime values. `config/config.yaml` holds the runtime settings:

```yaml
max_retry: 3           # read by the framework backbone's routing
timeout_s: 30          # per-call HENNGE budget, forwarded to the integration
hennge:
  base_url: "https://api.hennge.one/v1"
```

`requires.secrets` is **empty on purpose**. `HENNGE_API_TOKEN` is read with
`ctx.secrets.get()`, not `.require()`, and the shipped default transport is
network-free, so the agent runs correctly without it. Declaring it would make
the registry refuse to compile the agent wherever it is not provisioned — for a
credential the shipped configuration does not need.

### How settings reach the pipeline

Nodes take **no constructor arguments** (SDK v1 nodes are no-arg; configuration
never rides on node instances), so a declared value has to be carried:

1. `src/api/server.py` passes `load_runtime_config()` into the graph
   constructor. Constructing the agent with no config is the failure mode worth
   naming: `max_retry` and every other root key would simply never be read.
2. `HenngeWorkflowGraphNode._parent_config()` reads `config/config.yaml`,
   merges the root-level `timeout_s` into the `hennge:` settings (that is where
   its consumer looks for it), and forwards them under
   `config["configurable"]` — never `{}`.
3. The inner graph's `_extra_initial_state()` injects those settings into State
   as a JSON string (`hennge_config`), where `CallHenngeApiNode.execute(state,
   config=None)` reads them. An explicit `config["configurable"]["hennge"]`
   override is also honoured for direct invocation.

`tests/proof_of_boundary/test_pb_invoke_endpoint.py` proves the chain
behaviourally: a declared budget of `0.0` makes a real `/invoke` fail, and the
shipped configuration makes the same request succeed.

### The caller-data contract

Structured caller data arrives as the SDK's first-class `input_context`
parameter on `/invoke` and is validated by `PreProcessNode`:

| Field | Rule |
|-------|------|
| `user_id` / `user_hint` / `account_id` | must be a string matching `^[A-Za-z0-9][A-Za-z0-9_-]{0,19}$`; a present-but-malformed value is refused, never silently dropped |
| any other key | never read as a field, but still screened |
| whole payload | screened depth-first, keys included, for chat-template control tokens (`<|...|>`, `[INST]`, `<<SYS>>`) and instruction-override directives |
| request text | screened twice — raw (before markup stripping can delete a token) and sanitized (after stripping can re-assemble a split directive) |

The identifier bound is not decoration: `user_id` renders into the confirmation
message and the record reference, so an unbounded value there is
caller-controlled output. There is **no caller-controlled numeric field** in
this template; the one numeric setting (`timeout_s`) is operator-declared and
goes through a finite+bounded parser, because NaN and ±Infinity survive
`float()` and then compare False against every bound.

Structured data must travel in `input_context` rather than inside the request
text, because the framework masks personal data in the text channel — an
identifier written into the prose can arrive at the API call already rewritten.
`GraphNode.execute()` does not forward `input_context` to a subgraph, so the
validated value is carried across the boundary inside the `validated_input`
JSON envelope that `extract_input()` hands to the inner graph.

## Security design

- **Trust gate** — the single external trust gate is on the outer backbone
  `PreProcessNode.required_trust_level = TrustLevel.VERIFIED_EXTERNAL`; every inner
  domain node — **including the write-capable `CallHenngeApiNode`** — declares
  `TrustLevel.ANONYMOUS`. `GraphNode.execute()` forwards the caller's
  `InvocationContext` into the subgraph **unchanged** (no elevation), and
  `VERIFIED_EXTERNAL (1) < INTERNAL (2)`, so declaring an inner node `INTERNAL`
  would deny a legitimate external caller before the call runs — the boundary
  is therefore enforced exactly once, at `pre_process`. Agent-level default trust
  `VERIFIED_EXTERNAL` is declared in `config/agent.yaml`. `src/api/server.py`
  enforces the standalone entry-point Bearer-token auth boundary
  (`INVOKE_AUTH_TOKEN` -> VERIFIED_EXTERNAL elevation).
- **Input refusal is the template's own** — `PreProcessNode` screens and refuses
  hostile content itself rather than relying on the framework's input gate. That
  gate blocks only high-confidence findings, only on `user_input` /
  `validated_input`, and does not see `input_context` at all; a template that
  leans on it returns SUCCESS on payloads it should have refused wherever the
  gate is absent, older, or looking elsewhere. The screen runs on the raw text,
  on the sanitized text, and depth-first over the parsed context including its
  keys. Refusal is proven by calling `execute()` directly, so no upstream gate
  can answer for it, and the assertions are behavioural — error status, nothing
  carried forward — never a gate's wording.
  Sanitizing is deliberately separate from refusing: the markup strip deletes
  `<|im_start|>` outright, so a screen that only saw sanitized text would
  forward the directive residue as ordinary prose.
- **Input flag-and-redact** — `ValidateInputNode.execute()` runs a
  deterministic (regex, not a model) scan for email addresses and
  access-token-like strings (`eyJ...`, `secret_...`, `sk-...`) and redacts them
  before any logging. An access-control request legitimately names a user and an
  application, so this is flag-and-redact for safe logging, not a hard reject;
  the framework additionally masks emails/phones/names in
  `user_input`/`validated_input`. The only deterministic auto-reject here is the
  empty/non-request guard.
- **Secrets** — the integration token is read via
  `ctx.secrets.get("HENNGE_API_TOKEN")` (`InvocationContext.from_state(state)`),
  never `os.environ`, never stored in State. A missing token is tolerated **only**
  while the deterministic network-free stub transport is active (no live call is
  made); with a live transport injected, a missing token is a hard
  `status=error`.
- **Output boundary** — the domain output gate is the **module-level**
  `_security_gate_output()` in `src/nodes/post_process_node.py`, called from
  `PostProcessNode.execute()`. It blocks any SUCCESS response that lacks record
  evidence (record_id/record_ref) and any credential-shaped string anywhere in
  `formatted_output`, **walking nested structures** — a token riding inside the
  assembled request body is exactly the case a top-level-only scan misses.
  No node defines `_extra_security_gate_input/_output` instance methods
  (framework hooks are @final / auto-wrapped — domain checks live inline or in
  module-level helpers).
- **A refusal must contain, not merely label** — the framework assembles the
  caller envelope as `formatted_output or result` and that fallback ignores the
  status, so returning an error while leaving `result` in place would still
  deliver the un-checked inner answer inside the error envelope. **Every** error
  return — the gate violation AND the pre-existing inner-workflow failure —
  therefore clears every output-bearing field, through the one module-level
  `_contain()` helper. The caller-visible error is a **closed set**:
  `formatted_output` on a non-success path is exactly `{"reason": <code>}`, and
  nothing is read from `error_log`, the gate's violation entries or an
  exception message — those lines can carry an upstream API error body,
  identifiers and names, and truncation, path stripping or credential-only
  redaction of them is not a closed set. `error_log` stays the internal channel
  (state reducer + audit trail); the base envelope never projects it.
- **No error envelope carries HENNGE record evidence** — both error returns are
  built by the same `_contain()` helper: a constant reason code
  (`hennge_workflow_failed` / `output_withheld_by_gate`, the module's
  `ERROR_REASONS`) and nothing else — nothing read out of the record, nothing
  read out of the log. `record_id`/`record_ref` are this
  agent's write evidence — the gate REFUSES a SUCCESS that lacks them — so an
  ERROR envelope carrying them would tell a caller being informed of failure
  that an access record was nonetheless touched, and which one. HENNGE One is an
  identity/access system: the user id, the application label and the
  grant/revocation references are personal data and the audit trail of a
  privileged write. The reason code is a constant, which keeps the mapping
  TRUTHY — a falsy `formatted_output` would re-open the `or result` projection
  the containment exists to close.
- **Error reasons are closed-set labels** — `error_log` is the audit channel
  and is never projected to the caller, but a reason that interpolates the
  user id still records the account by another key. `call_hennge_api`
  therefore emits the HTTP status rather than the upstream error body (unbounded
  third-party text that can echo the account it refused) and the exception TYPE
  rather than the transport error string (whose request URL embeds the user id).
- **Numeric output invariant: not applicable.** This template renders record
  identifiers, references and a confirmation sentence — no monetary or
  otherwise rounded aggregate — so there is no precision grid to enforce and no
  numeric rewriting anywhere in the output path. The invariant this output
  boundary does enforce is the one stated above: a SUCCESS response carries
  record evidence, and no representation of the output carries a credential.
- **Audit** — every node's `execute()` emits at least one positional
  `emit_trace_event("<event>", {small non-PII payload}, state)` on a reachable
  path (intent / presence signals only — never request text, user or app
  content, or credentials). `__call__()` is never overridden. Event names
  (documented for operations):

  | Node | Audit event |
  |------|-------------|
  | pre_process | `pre_process_complete`, `pre_process_refused` |
  | validate_input | `validate_input_complete` |
  | classify_intent | `classify_intent_complete` |
  | infer_hennge_fields | `infer_hennge_fields_complete` |
  | call_hennge_api | `call_hennge_api_complete` |
  | confirm | `confirm_complete` |
  | post_process | `post_process_complete`, `post_process_output_blocked` |

## Implementation Note — model-backed synthesis

Intent classification (`ClassifyIntentNode`) and application-name inference
(`InferHenngeFieldsNode`) are model-backed: the keyword heuristic and the
regex/line-structure extraction are always computed first as the
baseline/fallback, and a real Azure OpenAI call (`AzureOpenAIClient`, built
fresh per invocation inside `execute()`, never cached on `self`) overrides
each when the three secrets are provisioned and the response parses as
well-formed JSON. Any LLM failure — an absent/invalid secret
(`ctx.secrets.require(...)` raising `MissingSecret`), an API error, or a
malformed/out-of-set response — silently degrades to the heuristic result;
`execute()` never raises and `status` never becomes `error` on this account.
The manifest declares `generation_mode: "llm"` and
`requires.extras: ["openai"]` accordingly.

**user_id stays fully deterministic regardless** — the LLM is never asked
for it and never trusted with it even if a response smuggled one in; only
`_resolve_id()`'s explicit-text/hint resolution can ever populate it. This
preserves the existing risk mitigation (never grant/revoke access on the
wrong user account) unchanged. Attribute (`Key: value`) extraction for the
API request body also stays deterministic, for the same reason one level
down: those values reach the live HENNGE API, not just the confirmation
message, so free-text invention there is a real side-effect risk.

Both LLM calls take a `llm: Any = None` constructor parameter as a
**unit-test seam only** — production wiring (`register_nodes()`) never
passes one, so every real invocation builds an `AzureOpenAIClient` from
`InvocationContext.from_state(state).secrets`.

## Limitation — HENNGE client (documented)

`src/services/hennge_client.py` is a self-contained service-layer client
(injectable transport, `HenngeApiError`, per-call token, no framework imports)
that ships a **deterministic, network-free stub** as its default transport: it
returns HENNGE One Admin-API-shaped responses (an `access_data` list for
app-access lookups; a `policy_data` list for policy checks; a task/receipt shape
with a synthetic grant/revocation id echo for grant/revoke, derived from the
request) so the pipeline is runnable and testable without a live HENNGE One
tenant or an HTTP library. It does **not** perform a live HENNGE call — the
rule being followed is: never fake a live call, document the limitation.

To go live, inject real `post`/`get` transports at construction. The transport
contract is `(url, headers, json_body, timeout_s) -> (status_code, body)`; a
live implementation passes `timeout_s` to its own HTTP call so the wait is
bounded at the socket, and the client re-checks elapsed time so an answer that
arrives after the budget is discarded rather than acted on. The method contracts
follow the HENNGE One Admin API resource model (users, application access,
policies), so going live is a transport injection plus (at most) endpoint-path
alignment — no business-logic change. (The stub also runs without a live
credential — see the secrets note above; a live transport requires
`HENNGE_API_TOKEN`.)

## Framework Utilization

### Shared Components Used
- [x] InvocationContext — read in `CallHenngeApiNode` via `InvocationContext.from_state(state)` (secrets + trust)
- [x] Trust gate — single external gate `PreProcessNode.required_trust_level = TrustLevel.VERIFIED_EXTERNAL`; inner domain nodes (incl. `CallHenngeApiNode`) declare `TrustLevel.ANONYMOUS` (caller `InvocationContext` forwarded unchanged into the subgraph)
- [x] Secrets — `ctx.secrets.get("HENNGE_API_TOKEN")`; entry-point `bound_secrets` / `secrets_factory` / `provision_secrets` in `src/api/server.py`; optional by design, so `config/agent.yaml requires.secrets` is empty
- [x] `emit_trace_event()` — at least one positional call per node on a reachable path; framework lifecycle events (node_start/node_complete/node_error) NOT re-emitted

### Composition Pattern

- **Pattern**: GraphNode (subgraph) — Cat 2 outer/inner split.
- **Composition target**: inner `HenngeWorkflowGraph` (`BaseGraph`) via `HenngeWorkflowGraphNode.get_subgraph()`.
- **Config forwarding**: `HenngeWorkflowGraphNode._parent_config()` loads
  `config/config.yaml` and forwards the `hennge` settings (with the root-level
  `timeout_s` merged in) under `config["configurable"]` to the subgraph.
- **Error propagation strategy**: `propagate` (default) — inner errors re-raised as
  `SubgraphError`; per-step `status=error` + `error_log` for API/validation failures
  (no silent pass).

## Import Isolation Confirmation
- [x] Template imports `framework/` and `shared/` only; the platform SDK is never imported directly
- [x] `src/services/hennge_client.py` and `src/services/security.py` have no
      framework imports (pure service layer, stdlib only)

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | AgentBaseGraph | AutonomousBaseGraph | AgentBaseGraph | Fixed multi-step pipeline (Cat 2), not an autonomous loop |
| Composition pattern | flat Cat 1 (MainNode) | GraphNode + inner subgraph | GraphNode + inner subgraph | Cat 2 must not be flat — `gate-composition`; 5 domain steps live in the inner graph |
| Model dependency | model client in the pipeline, no fallback | model call overrides a deterministic heuristic baseline, graceful degrade on any failure | override-with-fallback | richer NL classification/extraction without giving up testability or an LLM-outage failure mode; see "Implementation Note" |
| Model scope | let the LLM also resolve `user_id` / attributes | LLM limited to `intent` + `app_name`; `user_id` and attributes stay deterministic-only, never LLM-read or LLM-trusted | limited scope | `user_id` reaches a real grant/revoke call and attributes reach the live API body — free-text invention there is a side-effect risk, not just a confirmation-message one; see "Implementation Note" |
| HENNGE client | live HTTP call | injectable transport + documented stub default | injectable + stub default | no live network from the shipped default; document the limitation; go-live is a transport injection, no logic change |
| Node configuration | ctor-arg dependency injection | no-arg nodes + config forwarding via `_parent_config()` -> `configurable` -> state | no-arg nodes (`llm: Any = None` test seam excepted) | SDK v1 nodes are no-arg (ctor args TypeError at graph build); `config/config.yaml` stays the single runtime source. `ClassifyIntentNode`/`InferHenngeFieldsNode` take one *optional, defaulted* `llm` param as a unit-test double seam only — `NodeClass()` still constructs with zero args in `register_nodes()` |
| Declared secret (HENNGE) | declare `HENNGE_API_TOKEN` in `requires.secrets` | leave `requires.secrets` empty | empty | the key is read with `.get()`, not `.require()`, and the shipped transport needs none; declaring it makes the agent refuse to compile wherever it is not provisioned |
| Declared secret (Azure OpenAI) | leave `requires.secrets` empty (silent LLM no-op) | declare all three (`AZURE_OPENAI_API_KEY`/`_ENDPOINT`/`_DEPLOYMENT`) | declared | `.require()` inside a broad try/except is the graceful-degrade seam at runtime; `requires.secrets` is what registry compile-time provisioning reads — declaring it is how a real deployment gets asked to provision the secrets, at the cost of `require_at_compile()` refusing to compile a registry-mediated deployment missing any of the three (the standalone `src/api/server.py` entry point is unaffected — not registry-gated) |
| Blocked output | return an error status | return an error AND clear every output-bearing field | clear the fields | the caller envelope falls back to `result` regardless of status, so a status alone still ships the un-checked answer |
| Write target | infer user id from NL freely | caller-supplied/explicit id only; unresolved left empty | explicit only | never grant/revoke access on the wrong user account; unresolved id -> status=error, not invented |
| Default intent | grant_access | lookup_access | lookup_access | low-confidence classification must never default to a write |
