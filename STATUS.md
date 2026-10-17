# Implementation and verification status

This file distinguishes target design from shipped code. No profile may be called
complete merely because its design documents or interfaces exist.

| Area | Current implementation | Verification boundary |
| --- | --- | --- |
| Configuration/package | Typed JSON, empty sources, src layout, packaged migration | Local tests, installed wheel and v1-to-v2 migration CI |
| Evidence/core storage | Hashed immutable objects, PostgreSQL records/version heads | Local object tests; native PostgreSQL tests in CI |
| Jobs | Bounded retries, attempt events, cancellation, renewal and atomic chunk worker | PostgreSQL failure/concurrency tests; distributed/remote effects remain pending |
| Collection | RSS/Atom entry extraction and bounded public HTTP transport | Disposable parser, per-source exclusion, partial-run receipts and replay tests; full adversarial HTTP coverage remains pending |
| MCP | Five stdio reads with strict schemas, reader checks and bounded errors | Real SDK client against PostgreSQL in CI |
| Retrieval | Local ONNX embeddings, token-aware chunks, exact pgvector/RRF and generation activation/rollback | Synthetic numerical ONNX and native database/MCP tests; pretrained semantic quality, ANN, automatic backfill, caches and reranking pending |
| Local inference | Bounded CPU embedding runtime and process-shared encoder admission | No local text generation, GPU serving or cross-workload resource scheduler yet |
| Enrichment/graph/briefings | Target specification and evidence-span primitive | Complete jobs/validators/quality suite pending |
| Vulnerability/regulatory profiles | Target specification | No domain adapters or applicability verification yet |
| Cloud APIs/accounting/batches | Target specification | No credential access, native adapters, remote requests or spending |
| Remote MCP | Target authentication design | No HTTP listener or remote client compatibility claim |
| Export/recovery/retention | Target specification | No complete backup/restore/GC/publisher workflow yet |
| Publication controls | Positive file selection and source/artifact scanning | Narrow scanner tests; private values are never committed |

Schema v2 is additive; the published v1 SQL remains byte-identical. Job cancellation
revokes acceptance authority; it does not prove a running computation has stopped.
The worker currently processes `document.accepted` only, preserving other job kinds.
Character chunks preserve offsets but are not token-aware model input.

The full programme covers 28 capability areas, 18 ADRs, 58 requirements and 51
acceptance scenarios. The tests in this repository currently establish only a
foundation subset. Detailed future specifications are under `docs/`; they are not
execution receipts. CI results are authoritative for a particular tested revision.

Next dependency order: complete recovery tooling and retrieval quality/reranking,
local generation, enrichment/graph/products, domain profiles, governed cloud/remote MCP,
then integrated profile quality, failure, recovery and publication acceptance.

Do not copy private source catalogs, generated products, original deployment files,
or operational history to accelerate this roadmap. Prototype behaviour must be
reviewed and improved where it fails the target contracts.
