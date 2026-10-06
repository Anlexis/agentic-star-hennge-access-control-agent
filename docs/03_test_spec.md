# Test Specification - CMN-C2-282 HENNGE Access Control Agent

## Test Strategy
- Test types: Unit (per node + service + config + inner graph) / Proof-of-Boundary
  (full outer-graph invoke, the real ASGI `/invoke` entry point, import isolation,
  state safety, server boot, HITL stub).
- Location: `tests/unit/`, `tests/proof_of_boundary/` (`tests/integration/` is an
  empty package; end-to-end coverage lives in PB-6 and PB-8, which drive the real
  compiled outer graph).
- The HENNGE call is exercised through the deterministic, network-free stub
  transport (default) and through injected fake transports; no live HENNGE call.
- **Trust-gate routing canon**: every per-node unit test invokes the node as
  `node(state)` - `BaseNode.__call__` routes the full security pipeline (trust
  gate -> input gate -> `execute()` -> output gate) - never bare
  `node.execute(state)`. State builders set `caller_trust_level =
  TrustLevel.VERIFIED_EXTERNAL.value` for PreProcessNode (the single external gate)
  and `TrustLevel.ANONYMOUS.value` for every other node. The trust-rejection test
  asserts on the RETURNED error dict (`status == AgentStatus.ERROR.value`, "trust
  gate denied" in `error_log`, execute-only keys absent) - `__call__` never raises
  for a trust denial.
- **Two documented exceptions to that canon**, both deliberate:
  1. `CallHenngeApiNode.execute(state, config=...)` — the config-override test
     needs a 2nd argument that `__call__` cannot forward.
  2. The refusal tests in `test_pre_process_node.py` call `execute()` DIRECTLY.
     Routing them through `__call__` would let the framework's own input gate
     answer first, and a test that passes because something upstream refused
     proves nothing about the node that has to hold when that gate is absent,
     older, or looking at a channel it does not cover. Assertions there are
     behavioural — error status, nothing carried forward — never a gate's wording.
- Assertion contract: the invoke surface is `result["output"]` / `status` /
  `trace_id` / `correlation_id` / `node_history` (never `formatted_output` at the
  invoke surface); status is compared to `AgentStatus.SUCCESS`/`.value` (lowercase
  `success`/`error`); the outer graph is called as
  `invoke(user_input=..., ctx=..., input_context=...)`; identifiers may be masked
  (`[MASKED]`) so record evidence is asserted by presence, not raw repr; audit
  spies assert on `call.args[1]` (the event payload), never the whole-call repr.
- Framework pipeline behaviours encoded by the suite: `__call__` short-circuits on
  an incoming errored state (execute() is skipped; error status/error_log pass
  through); the framework's PII mask rewrites Title-Case bigrams (across
  newlines), emails, and digit groups in `user_input`/`validated_input` to
  `[MASKED]` before `execute()` sees the text - positive payloads are PII-free
  (HENNGE user ids like `u-1001`, no `@`), intentional-PII tests assert the
  `[MASKED]` path.
- Domain audit events are muted per module via an autouse fixture patching
  `src.nodes.<mod>.emit_trace_event` (never a `sys.modules` stub of `shared.*`).

## Unit Tests (`tests/unit/`)

| TC-ID | Test file | Focus | Expected |
|-------|-----------|-------|----------|
| U-01 | test_trust_gate.py | trust boundary: ANONYMOUS caller on the VERIFIED_EXTERNAL pre_process gate; inner nodes ANONYMOUS; trust-posture declarations | denial RETURNS an error dict (`status == AgentStatus.ERROR.value`, "trust gate denied" in error_log, execute-only keys absent); VERIFIED_EXTERNAL passes; every inner node declares ANONYMOUS |
| U-02 | test_pre_process_node.py | the caller-data contract: serialize NL request + validated hint into `validated_input` (JSON); markup strip; hint priority user_id > user_hint > account_id; hostile-content refusal; identifier lock; legitimate-prose control set | hint resolved by priority; `<script>` stripped; empty/missing -> `status=error`; control tokens (`<\|...\|>`, `[INST]`, `<<SYS>>`), directives, hostile keys and nested payloads refused with nothing carried forward; non-inert / non-string identifiers refused without echoing the value; hostile unrecognised field names masked; real access-control sentences pass |
| U-03 | test_validate_input_node.py | empty/short guard; JSON-shaped input; framework `[MASKED]` path for emails; node-level token flag-and-redact (`secret_*`) | email -> `[MASKED]` before execute; token -> `[REDACTED]` + `redaction_flags=["token"]` (JSON string); empty/short -> error; audit payload carries flags only |
| U-04 | test_classify_intent_node.py | intent = lookup_access / grant_access / revoke_access / check_policy (keyword baseline, writes-first priority, policy above lookup, read-only default); model-backed override (`TestClassifyIntentNodeLlmPath`): well-formed/fenced-JSON override, out-of-set/malformed/raising LLM response falls back to keyword, no-llm-injected-and-no-secret-bound falls back to keyword, empty input never calls the LLM, audit event source field | correct intent per keyword; no-signal defaults to lookup_access with a non-fatal note; empty -> error (LLM never called); audit event emits the intent label + `source` (`"keyword"`/`"llm"`) only; any LLM failure/malformed/out-of-set response silently falls back to the keyword result, never a hard error |
| U-05 | test_infer_hennge_fields_node.py | HENNGE user-id resolution (text > id-shaped hint > `Account:` field; never invented, NEVER LLM-derived); quoted app name filtered to a renderable alphabet, with a model-backed override (`TestInferHenngeFieldsNodeLlmPath`: well-formed/fenced-JSON override, null/malformed/raising LLM response falls back to the heuristic, a smuggled `user_id` key in the LLM response is never read, no-llm-injected-and-no-secret-bound falls back to the heuristic, empty input never calls the LLM); `Key: value` attribute fields (deterministic-only, never LLM-touched); HENNGE One Admin API request body per intent (JSON string) | lookup/check_policy `{user_id}`; grant/revoke `access_request[0]` with user_id/app_name/attributes; unresolved id left `""`; empty input -> error (LLM never called); `user_id` unaffected by any LLM response in every LLM-path case; any LLM failure/malformed/null response silently falls back to the regex/quote heuristic for `app_name`, never a hard error |
| U-06 | test_call_hennge_api_node.py | lookup/policies/grant/revoke via the network-free stub; `hennge_config` state field + `execute(state, config=...)` override (documented direct-execute exception); API error / unresolved id / unknown intent / missing payload; secret posture (a live transport refuses to run unauthenticated; token read via `ctx.secrets`, never env/state) | record_id/record_ref on success (`hennge://users/...` / `hennge://access-grants/...` / `hennge://access-revocations/...`); 403 surfaces in error_log; live+no-secret -> error "unauthenticated"; live+bound secret -> token passed to the client; audit event emits presence signals with `stub_transport=True` |
| U-07 | test_confirm_node.py | human-readable confirmation per intent verb; ref/id formatting; app/user target fallback | "Retrieved app access status / Granted app access / Revoked app access / Retrieved policy assignments ... ref=... id=..."; missing evidence -> error |
| U-08 | test_post_process_node.py | `formatted_output` shaping (payload round-trip, user/app/intent surfaced); errored state passes through `__call__` un-masked (short-circuit); the record-evidence and credential checks in the module-level `_security_gate_output()` helper, including NESTED values; containment of a blocked response; the closed-set ERROR envelope on every non-success path | success shape with parsed `hennge_payload`; error status/error_log preserved, no success shape fabricated; SUCCESS without record_id/record_ref blocked ("output gate"); a credential nested inside `hennge_payload` blocked, a credential-shaped mapping key blocked with the key withheld from the label, and a clean nested payload passes as the control; on a violation EVERY output-bearing field is cleared and no released text survives; on every non-success path (inner error, inner error with the answer in `result`, credential in `error_log`, missing record evidence, credential nested in the payload, credential-shaped key) `formatted_output` is exactly `{"reason": <code>}` with the code in `ERROR_REASONS`, a sentinel seeded in `error_log` appears nowhere in the returned mapping (nested keys and values walked), the inner entries are not re-emitted, gate violations travel in `error_log` only, and the audit events carry a reason code and a count only |
| U-09 | test_hennge_client.py | HENNGE One Admin REST API client: user-access / policies lookups, access grant/revoke; `Authorization: Bearer` header; `HenngeApiError` on non-2xx; stub shapes (`access_data` / `policy_data` / task receipt + grant_id/revocation_id echo, `_stub` marker); `uses_stub_transport`; the `timeout_s` transport contract | correct URLs/headers/bodies; 400 raises with joined `errors`; stub deterministic shapes; the configured budget reaches the transport and an overrun raises 504 rather than returning a late answer |
| U-10 | test_config.py | `config/agent.yaml` (flat manifest) + `config/config.yaml` (runtime) and the forwarder that reads them | root-level id CMN-C2-282, Cat 2, CMN, ToolCallingAgent, dotted `class` entry point, VERIFIED_EXTERNAL, `generation_mode: llm`, `requires.secrets` = the three Azure OpenAI keys, `requires.extras: ["openai"]`; no nested `agent:` block; runtime file carries `max_retry`/`timeout_s`/`hennge.base_url`; `_parent_config()` returns exactly those values |
| U-11 | test_domain_workflow_graph.py | inner `HenngeWorkflowGraph`: identity, `_extra_initial_state()` hennge_config JSON injection, `route()` error short-circuit, `get_output` contract, compile, direct inner invoke on the stub | name/state_schema correct; config forwarded as a JSON string; error -> END; inner invoke runs validate -> classify -> infer -> call -> confirm to SUCCESS with record evidence |
| U-12 | test_framework_compliance_tc06_tc07.py | the framework's @final gate methods cannot be overridden by a domain node | TC-06 / TC-07: overriding the default input / output gate raises at class-definition time |

## Proof-of-Boundary Tests (`tests/proof_of_boundary/`)

| PB-ID | Boundary | Test | Expected |
|-------|----------|------|----------|
| PB-4 | Import isolation | test_import_isolation.py | AST scan of `src/`: no direct platform-SDK import |
| PB-2/PB-5 | State serialization | test_state_safety.py | `state.py`: no Pydantic/credential fields |
| PB-6 | Backbone invoke-order + external-trust | test_pb_invoke_order.py | `_VALID_PAYLOAD` byte-equal to `deploy/invoke_payload.json` "input" (asserted); VERIFIED_EXTERNAL caller yields `status=success` with `node_history == [InitializeNode, PreProcessNode, HenngeWorkflowGraphNode, PostProcessNode, FinalizeNode]` and record evidence + confirmation in `result["output"]`; ANONYMOUS caller denied at pre_process (error, no post_process, no output); blank input -> error, not crash |
| PB-7 | HITL interrupt propagation *(conditional)* | test_pb7_hitl_interrupt_propagation.py | **Auto-waived - non-HITL** (`config/agent.yaml` has no `hitl.enabled: true`): module-level skipif; stub bodies are real AssertionErrors so enabling HITL without implementing PB-7 fails loudly |
| PB-8 | The real ASGI `/invoke` entry point | test_pb_invoke_endpoint.py | caller-supplied `input_context` reaches the inner graph and drives the call (a request text naming no user still returns a confirmation for the supplied one); every intent path reachable; missing/wrong Bearer token -> 401 with a generic body; malformed caller metadata refused without echoing the value; bare `NaN`/`Infinity` in a raw JSON body refused on type; oversized input / context / entry count -> 413; injection content (control tokens, override phrasing, hostile field names, `\u`-escaped payloads) refused with nothing carried forward; a declared `timeout_s` of `0.0` makes a real invoke fail while the shipped config succeeds (the control); a blocked response ships a TRUTHY withheld notice (`reason=output_withheld_by_gate`) with no released text, no record reference, no traceback and no source paths; no credential-shaped string anywhere in the response body |
| PB (containment) | The ERROR envelope | test_error_envelope_no_record_evidence.py | the error envelope is present AND truthy (a falsy one re-opens `formatted_output or result`), names no `record_id`/`record_ref`/`user_id`/`app_name`, the delta CLEARS every output-bearing state field, and the error status is still reported — plus a clean-path control so the containment assertions cannot pass vacuously. Error reasons carry closed-set labels only: the HTTP status not the upstream body, the exception TYPE not the transport string, the intent not the account. **Reachability:** this branch is not reachable through the compiled graph (`route()` sends ERROR to `finalize`; `BaseNode.__call__` short-circuits an already-errored state), so the tests call `execute()` directly — source-level defence in depth |
| PB (containment) | The caller-visible ERROR envelope | test_output_envelope_containment.py | through the agent's own `get_output()` after the state reducer's merge: on every non-success path (inner-workflow error, missing record evidence, credential nested in the payload, credential-shaped mapping key) the envelope is exactly `{"reason": <code>}` with the code in `ERROR_REASONS` and stays truthy; a sentinel seeded in `error_log` (a name and a runtime-assembled credential-shaped token inside an echoed body) is absent from the envelope and from every merged field but `error_log`, where it appears once; a violation names its path in `error_log` and never enters the envelope; a credential-shaped key is withheld from the label with `result` still cleared; a caller's field name reaches neither the envelope nor the label; clean-path controls still ship the answer. Through the real ASGI `/invoke`, with the sentinel seeded by the last inner node and a spy proving it reached post_process: a refused response is `{"reason": "output_withheld_by_gate"}` with no `error_log` key and the sentinel, the violation labels, the record reference and the id nowhere in the body (nested keys and values walked); an inner failure ships no output, no `error_log` and no sentinel (post_process does not run — the backbone routes an error to finalize); the clean control still ships the answer and never the log |
| PB (boot) | Server entry point | test_server_boot.py | importing `src.api.server` does not raise (construct + compile + provision_secrets at import); agent constructs + compiles via the supported path; `/invoke` + `/health` routes exposed |

> PB-1 (audit emission) is covered inside the unit suite via the emit-spy tests
> (validate / classify / call nodes assert on the event payload, `call.args[1]`).
> PB-3 (live external service) is not exercised in this suite - the shipped
> transport is the documented network-free stub.

## Test Execution Summary
- Execution date: 2026-08-31
- Runner: `python -m pytest tests -q` against the framework wheel CI installs
  (`agenticstar-agentcore[marketplace,openai,platform-rag,platform-memory,platform-db,platform-storage-azure]==1.0.2`)
- Total tests: 184
- Pass: 182 / Fail: 0 / Skip: 2 (PB-7 A/B - auto-waived, non-HITL)
