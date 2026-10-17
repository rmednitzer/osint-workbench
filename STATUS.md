# Implementation and verification status

This file distinguishes target design from shipped code. No profile may be called
complete merely because its design documents or interfaces exist.

| Area | Current implementation | Verification boundary |
| --- | --- | --- |
| Configuration/package | Typed JSON, empty sources, src layout, packaged migration | Local tests, wheel inspection and CI |
| Evidence/core storage | Hashed immutable objects, PostgreSQL records/version heads | Local object tests; native PostgreSQL tests in CI |
| Jobs | Enqueue, dedup, expiring claims, fencing and completion | PostgreSQL tests in CI; cancellation/outbox dispatch lifecycle remains incomplete |
| Collection | RSS/Atom entry extraction and bounded public HTTP transport | Parser/address/resolver tests; full adversarial HTTP/parser coverage remains pending |
| MCP | Five stdio reads with strict schemas, reader checks and bounded errors | Real SDK client against PostgreSQL in CI |
| Retrieval | Lexical search; dimension/identity/fusion primitives | Primitive tests only; real embeddings, chunk tokenization, pgvector, backfill and reranking pending |
| Local inference | Target specification | No model serving, resource scheduler or actual model verification yet |
| Enrichment/graph/briefings | Target specification and evidence-span primitive | Complete jobs/validators/quality suite pending |
| Vulnerability/regulatory profiles | Target specification | No domain adapters or applicability verification yet |
| Cloud APIs/accounting/batches | Target specification | No credential access, native adapters, remote requests or spending |
| Remote MCP | Target authentication design | No HTTP listener or remote client compatibility claim |
| Export/recovery/retention | Target specification | No complete backup/restore/GC/publisher workflow yet |
| Publication controls | Positive file selection and source/artifact scanning | Narrow scanner tests; private values are never committed |

The full programme covers 28 capability areas, 17 ADRs, 58 requirements and 51
acceptance scenarios. The tests in this repository currently establish only a
foundation subset. Detailed future specifications are under `docs/`; they are not
execution receipts. CI results are authoritative for a particular tested revision.

Next dependency order: complete acquisition/recovery semantics, retrieval/local
inference, enrichment/graph/products, domain profiles, governed cloud/remote MCP,
then integrated profile quality, failure, recovery and publication acceptance.

Do not copy private source catalogs, generated products, original deployment files,
or operational history to accelerate this roadmap. Prototype behaviour must be
reviewed and improved where it fails the target contracts.
