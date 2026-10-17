# Implementation and verification status

This file distinguishes target design from shipped code. No profile may be called
complete merely because its design documents or interfaces exist.

| Area | Current implementation | Verification boundary |
| --- | --- | --- |
| Configuration/package | Typed JSON, empty sources, src layout, packaged migration | Local tests, installed wheel and v1-to-v2 migration CI |
| Evidence/core storage | Hashed immutable objects, PostgreSQL records/version heads | Local object tests; native PostgreSQL tests in CI |
| Jobs | Bounded retries, attempt events, cancellation, renewal and atomic chunk worker | PostgreSQL failure/concurrency tests; distributed/remote effects remain pending |
| Collection | RSS/Atom entry extraction and bounded public HTTP transport | Disposable parser, per-source exclusion, partial-run receipts and replay tests; full adversarial HTTP coverage remains pending |
| MCP | Seven stdio reads with strict schemas, reader checks and bounded errors | Real SDK client against PostgreSQL in CI |
| Retrieval | Local ONNX embeddings, token-aware chunks, exact pgvector/RRF and generation activation/rollback | Synthetic numerical ONNX and native database/MCP tests; Actual ONNX pair scoring added; pretrained semantic quality, ANN, automatic backfill and caches pending |
| Local inference | Bounded CPU embedding runtime and process-shared encoder admission | Native Unix-socket generation adapter, peer/artifact checks and durable uncertain ownership added; native CI pending; no GPU or complete cross-host scheduler |
| Enrichment/graph/briefings | Durable typed proposals, evidence spans, operator reviews and cited assertion digests | PostgreSQL/MCP tests added; semantic acceptance, aliases/merge, diversity and full quality suite pending |
| Vulnerability/regulatory profiles | Target specification | No domain adapters or applicability verification yet |
| Cloud APIs/accounting/batches | Target specification | No credential access, native adapters, remote requests or spending |
| Remote MCP | Target authentication design | No HTTP listener or remote client compatibility claim |
| Export/recovery/retention | Target specification | No complete backup/restore/GC/publisher workflow yet |
| Publication controls | Positive file selection and source/artifact scanning | Narrow scanner tests; private values are never committed |

Schema v3 is additive; published v1 and v2 migrations remain byte-identical. Job cancellation
revokes acceptance authority; it does not prove a running computation has stopped.
The core worker processes `document.accepted`; the explicit enrichment worker claims
only its configured generator identity. Other job kinds remain queued.
Character chunks preserve offsets but are not token-aware model input.

The full programme covers 28 capability areas, 19 ADRs, 58 requirements and 51
acceptance scenarios. The tests in this repository currently establish only a
foundation subset. Detailed future specifications are under `docs/`; they are not
execution receipts. CI results are authoritative for a particular tested revision.

Next dependency order: complete recovery tooling and retrieval quality/reranking,
local generation, enrichment/graph/products, domain profiles, governed cloud/remote MCP,
then integrated profile quality, failure, recovery and publication acceptance.

Do not copy private source catalogs, generated products, original deployment files,
or operational history to accelerate this roadmap. Prototype behaviour must be
reviewed and improved where it fails the target contracts.
