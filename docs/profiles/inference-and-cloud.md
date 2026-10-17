# Local inference, cloud APIs and governance

Scope: C12-C17 and C21. Cloud integration code is included; external activation is optional and denied by default. No paid call was performed for planning.

## Provider-independent task contract

Define task classes: embedding query/document, rerank, classification, structured extraction, summary, briefing, bounded analysis and advisory review. A request carries operation/attempt ID, task class, input artifact IDs/hashes and sensitivity, prompt/schema version, context/output limits, deadline, required capabilities and route policy. Responses preserve selected provider/model and reported resolved identity, finish/refusal/incomplete state, tool calls, structured output, usage dimensions, cache metadata and error classification.

Use a normalized result envelope while retaining raw provider metadata privately when policy permits. Never translate an unknown stop reason into success, silently discard refusal/length limits, invent missing usage or assume token meanings match across vendors. Streaming must handle fragmented UTF-8/tool JSON, cancellation and partial usage; a disconnected stream may have incurred remote cost. Structured-output validity is separate from evidence correctness.

## Local stack

Provide a tested llama.cpp server reference and common API client. Its documentation describes its API and serving features [S8], but actual pinned-version support must be tested. An external OpenAI-compatible local endpoint is supported only for declared capabilities; compatibility does not imply support for forced tools, parallel tools, streaming usage, JSON-schema enforcement or embeddings. Keep provider adaptation out of enrichment business logic.

Support explicit model manifests, model context/tokenizer templates, quantization, expected file hashes, code provenance and licenses. At least one genuinely useful small licensed local generation model and one encoder/reranker must pass actual CPU acceptance; GPU acceleration has a separate matrix of tested hardware/runtime/configuration. Do not bundle private model choices, weights or remote-code defaults. Test native structured/tool output; do not rely on stripping reasoning tags or cross-provider response conversion as correctness.

Resource admission is shared across generation, encoding and reranking: reserve configured memory/headroom and slots, use measured capacity, prefer interactive work without starving batch jobs, bound queues and expose admission refusal. A process lease identifies only owned workers. Cancellation releases a reservation only after confirming worker termination/resource ownership; a timeout does not prove cancellation. Handle OOM, model unload/reload, worker crash and drain/shutdown. Never kill ambient processes, unload a model owned by another workload or start replacement GPU work before the old worker is reaped. External unmanaged runtimes require a conservative contract or explicit incompatibility, not guessed memory ownership.

## Cloud support and sovereignty

Implement native OpenAI and Anthropic adapters plus a declared-capability OpenAI-compatible adapter for operator-selected services. Verify current native API contracts against official documentation during implementation; this plan does not freeze endpoints, API versions or prices. Endpoints/credentials/model catalogues are external config and no production account IDs/keys ship. Named US-provider compatibility does not constitute sovereignty approval.

Provider policy records controlling entity/jurisdiction, residency and remote access, foreign legal exposure including US CLOUD Act where material, retention/training use, subcontractors/control plane, key custody, portability and evidence date. Default sovereignty constraint permits local/EU-controlled approved routes; unknown or conflicting facts deny remote dispatch. An explicitly configured, task-scoped exception can enable a nonconforming provider without relabelling it sovereign. No EU-hosting-only compliance claim and no automatic waiver from installing an adapter.

Assign data classes at ingestion/workspace/task construction. Public origin does not prove absence of personal/sensitive material. Cloud release packets contain only explicitly selected fields/excerpts, with policy identifier, input hashes, classification rationale and authorized destination. Pattern/DLP checks are backstops, not proof of de-identification. Private context, source credentials and hidden conversation history are never appended automatically. Logs contain only redacted operational metadata; raw prompts/responses are off by default with documented opt-in restricted retention.

Persist route selection and budget reservation before dispatch. Fail closed on unknown classification, unapproved model/capability, policy/jurisdiction conflict or missing budget. Explicit fallback edges specify allowed task/data/model/provider and cost bounds. Local failure never implicitly enables cloud; cross-provider fallback cannot widen disclosure. Source/provider text cannot modify policy. A read-only local query remains available if remote policy denies a model job.

## Accounting, retries, batching and caching

Use a PostgreSQL ledger with logical operation ID, attempts and remote request/batch/custom IDs. Reserve a conservative token/cost upper bound transactionally before dispatch; reconcile observed usage and keep unresolved reservations pending on ambiguous completion. A timeout is outcome-unknown; do not replay chargeable work automatically without provider-supported idempotency/reconciliation or an explicit bounded policy. Do not claim exactly-once remote execution.

Separate input/output, cached read/write, reasoning and other billed dimensions according to native semantics. Preserve reported token counts and missing fields; distinguish estimate, observed usage and invoice/cost-export evidence. Use Decimal with explicit currency and dated pricebook versions. Do not sum EUR and USD or invent exchange rates; optional conversions require dated rate provenance and separately labelled totals. Provider errors, refused/truncated results and retries may still incur cost. Hard caps include concurrent workers and batch reservations, not just completed calls.

Batch lifecycle: prepared, submitted, accepting/processing, complete/partial/failed/cancel-requested/cancelled/expired/outcome-unknown, retrieved, validated, ingested. Persist IDs before subsequent polling, reconcile duplicate/missing custom IDs, partial results and late completions; cancel is not proof of no cost or deleted data. Quarantine malformed results and commit accepted rows idempotently. No automatic batch submission merely because a queue is nonempty.

Result reuse/cache keys include task/input hashes, source versions, model/provider/reported identity, prompt/schema/tool/policy versions and disclosure class. Model aliases have bounded reuse and explicit identity limits; remote providers do not expose reproducible weights merely by returning a model label. A route or policy change invalidates incompatible reuse. Use no cross-workspace private cache; test concurrency and schema/version mismatch.

Catalog refresh discovers candidates only. Promotion requires known capabilities, license/sovereignty disposition, frozen quality/resource/cost evaluation and an explicit configuration change. Detect deprecation, alias drift, access/entitlement failure and pricebook staleness; do not replace an unavailable model with an untested one. Keep provider-specific access programme metadata opaque/optional and never infer entitlement from a friendly model name.

## Verification and limits

Offline E2E exercises actual installed adapter code against fake provider HTTP endpoints for success, 401/403, 429/5xx, retry headers, malformed JSON/schema, refusal, truncation, tool fragments, missing usage, ambiguous timeout, duplicate submission, batch partial results and policy denial. Outbound sockets must be denied in local-only mode. Real local generation/embedding/reranking tests require actual models.

Offline provider fixtures prove contract handling only. A live smoke test requires an intentionally selected provider/model, non-sensitive synthetic input, declared maximum spend and existing task authorization; none is assumed here. Record contract-tested and live-provider-tested separately. If a release requires real-provider validation but it is unavailable, list it as blocked/outstanding rather than claim full cloud E2E success. Do not make purchases or request credentials during planning.
