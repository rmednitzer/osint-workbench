# Implementation and verification status

This file distinguishes target design from shipped code. No profile may be called
complete merely because its design documents or interfaces exist.

| Area | Current implementation | Verification boundary |
| --- | --- | --- |
| Configuration/package | Typed JSON, empty sources, src layout, packaged migrations | Installed-wheel CI covers retained core v1-to-v4 and active profile v1-to-v2 upgrade state |
| Evidence/core storage | Hashed immutable objects, PostgreSQL records/version heads | Local object tests; native PostgreSQL tests in CI |
| Jobs | Bounded retries, attempt events, cancellation, renewal and atomic chunk worker | PostgreSQL failure/concurrency tests; distributed/remote effects remain pending |
| Collection | RSS/Atom entry extraction and bounded public HTTP transport | Disposable parser, per-source exclusion, partial-run receipts and replay tests; full adversarial HTTP coverage remains pending |
| MCP | Seven stdio reads with strict schemas, reader checks and bounded errors | Real SDK client against PostgreSQL in CI |
| Retrieval | Local ONNX embeddings, token-aware chunks, exact pgvector/RRF and generation activation/rollback | Synthetic numerical ONNX and native database/MCP tests, including actual pair scoring; pretrained semantic quality, ANN, automatic backfill and caches pending |
| Local inference | CPU embedding/rerank runtimes, native Unix-socket generation and durable shared admission | Actual synthetic ONNX/GGUF execution and Unix transport/crash tests in CI; no GPU, pretrained quality or complete cross-host scheduler |
| Enrichment/graph/briefings | Durable typed proposals, evidence spans, operator reviews and cited assertion digests | PostgreSQL/MCP proposal, review, withdrawal and cited-digest tests passed; pretrained semantic acceptance, aliases/merge and diversity pending |
| Vulnerability/regulatory profiles | Target specification | No domain adapters or applicability verification yet |
| Cloud APIs/accounting/batches | Target specification | No credential access, native adapters, remote requests or spending |
| Remote MCP | Target authentication design | No HTTP listener or remote client compatibility claim |
| Export/recovery/retention | Bounded private checkpoint, empty-target restore, operator retention/holds/logical tombstones and mandatory current-policy reconciliation | Native SQL-reader, job/fence, inference, collector and restored-policy regressions passed in installed-wheel CI. Physical GC/erasure, legacy adoption, public export, publisher and full-host/PITR remain pending |
| Publication controls | Positive file selection and source/artifact scanning | Narrow scanner tests; private values are never committed |

Core schema v4 and retrieval-profile v2 are additive; earlier published migrations
remain byte-identical. Checkpoint format 2 requires separate policy receipts;
legacy format-1 restore/adoption is not silently accepted. Job cancellation
revokes acceptance authority; it does not prove a running computation has stopped.
The core worker processes `document.accepted`; the explicit enrichment worker claims
only its configured generator identity. Other job kinds remain queued.
Character chunks preserve offsets but are not token-aware model input.

The lifecycle implementation is backed by 103 installed-wheel tests with no skips,
including retained-state migration, direct SQL/MCP suppression, native retrieval,
concurrency and policy-gated isolated recovery. See
[the revision-bound receipt](docs/testing/verification-evidence.json). Synthetic
models establish execution contracts, not pretrained semantic quality.

The full programme covers 28 capability areas, 21 ADRs, 58 requirements and 51
acceptance scenarios. The tests in this repository currently establish only a
foundation subset. Detailed future specifications are under `docs/`; they are not
execution receipts. CI results are authoritative for a particular tested revision.

Outstanding dependency groups: physical deletion/GC, policy custody and wider recovery operations;
pretrained retrieval/generation quality and full resource scheduling; richer graph
and cited products; domain profiles; governed cloud and remote MCP; deployment,
observability and integrated failure, recovery and publication acceptance. Existing
bounded implementations do not close these programme-wide areas.
See [the remaining implementation and acceptance ledger](docs/implementation-backlog.md)
for concrete closure evidence across every unfinished workstream.

Do not copy private source catalogs, generated products, original deployment files,
or operational history to accelerate this roadmap. Prototype behaviour must be
reviewed and improved where it fails the target contracts.
