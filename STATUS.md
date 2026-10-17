# Implementation and verification status

This file distinguishes target design from shipped code. No profile may be called
complete merely because its design documents or interfaces exist.

| Area | Current implementation | Verification boundary |
| --- | --- | --- |
| Configuration/package | Typed JSON, empty sources, src layout, packaged migrations | Installed-wheel CI covers retained core v1-to-v5 and active profile v1-to-v2 upgrade state |
| Evidence/core storage | Hashed immutable objects, PostgreSQL records/version heads | Local object tests; native PostgreSQL tests in CI |
| Jobs | Bounded retries, attempt events, cancellation, renewal and atomic chunk worker | PostgreSQL failure/concurrency tests; distributed/remote effects remain pending |
| Collection | RSS/Atom extraction, bounded public HTTP transport and durable due/validator state | Native HTTP sockets, parser, due/304/backoff, crash/replay and recovery tests passed. Full adversarial HTTP coverage remains pending |
| MCP | Seven stdio reads with strict schemas, reader checks and bounded errors | Real SDK client against PostgreSQL in CI |
| Retrieval | Local ONNX embeddings, token-aware chunks, exact pgvector/RRF and generation activation/rollback | Synthetic numerical ONNX and native database/MCP tests, including actual pair scoring; frozen offline scorer/local diagnostic added; pretrained semantic acceptance, ANN, automatic backfill and caches pending |
| Local inference | CPU embedding/rerank runtimes, native Unix-socket generation and durable shared admission | Actual synthetic ONNX/GGUF execution and Unix transport/crash tests in CI; no GPU, pretrained quality or complete cross-host scheduler |
| Enrichment/graph/briefings | Durable typed proposals, evidence spans, operator reviews and cited assertion digests | PostgreSQL/MCP proposal, review, withdrawal and cited-digest tests passed; pretrained semantic acceptance, aliases/merge and diversity pending |
| Vulnerability/regulatory profiles | Target specification | No domain adapters or applicability verification yet |
| Cloud APIs/accounting/batches | Target specification | No credential access, native adapters, remote requests or spending |
| Remote MCP | Target authentication design | No HTTP listener or remote client compatibility claim |
| Export/recovery/retention | Bounded private checkpoint, empty-target restore, operator retention/holds/logical tombstones and mandatory current-policy reconciliation | Native SQL-reader, job/fence, inference, collector and restored-policy regressions passed in installed-wheel CI. Reviewed orphan-object GC passed native failure/restart and scoped-role tests. Full record erasure, legacy adoption, public export, publisher and full-host/PITR remain pending |
| Publication controls | Positive file selection and source/artifact scanning | Narrow scanner tests; private values are never committed |

Core schema v5 and retrieval-profile v2 are additive; earlier published migrations
remain byte-identical. Checkpoint format 2 requires separate policy receipts;
legacy format-1 restore/adoption is not silently accepted. Job cancellation
revokes acceptance authority; it does not prove a running computation has stopped.
The core worker processes `document.accepted`; the explicit enrichment worker claims
only its configured generator identity. Other job kinds remain queued.
Character chunks preserve offsets but are not token-aware model input.

The installed-wheel suite has 138 passing tests with no skips,
including retained-state migration, direct SQL/MCP suppression, native retrieval,
concurrency and policy-gated isolated recovery. See
[the revision-bound receipt](docs/testing/verification-evidence.json). Synthetic
models establish execution contracts, not pretrained semantic quality.

The full programme covers 28 capability areas, 26 ADRs, 58 requirements and 51
acceptance scenarios. The tests in this repository currently establish only a
foundation subset. Detailed future specifications are under `docs/`; they are not
execution receipts. CI results are authoritative for a particular tested revision.

Outstanding dependency groups: full retained-record erasure and backup expiry, policy custody and wider recovery operations;
pretrained retrieval/generation quality and full resource scheduling; richer graph
and cited products; domain profiles; governed cloud and remote MCP; deployment,
observability and integrated failure, recovery and publication acceptance. Existing
bounded implementations do not close these programme-wide areas.
See [the remaining implementation and acceptance ledger](docs/implementation-backlog.md)
for concrete closure evidence across every unfinished workstream.

Do not copy private source catalogs, generated products, original deployment files,
or operational history to accelerate this roadmap. Prototype behaviour must be
reviewed and improved where it fails the target contracts.

Orphan GC adds an explicit bounded plan/apply CLI, complete retained-reference
checks, store/file identity checks and durable intent/completion receipts. The
native failure/restart and scoped-principal tests passed in the named CI receipt.
It never deletes retained database records or objects reachable from them.

Scheduled acquisition adds an explicit bounded due-only tick and private HTTP
validators. The core-v5 native acceptance cases passed in the named
verification receipt. A generic hardened collector service/timer and explicit disposable-runner acceptance script are provided; actual service acceptance is recorded separately from database-backed collection tests.

The new offline evaluator freezes suite, ranking, baseline and encoder identities
before inference and preserves negative gates and partial failure observations.
The bundled English/German suite is public and authored synthetic data, including
exposed held-out groups. It cannot establish independent semantic acceptance.
Model artifact preparation and reference-service acceptance are explicit manual
workflow activities; ordinary CI and imports never download pretrained weights.
The experimental multilingual encoder does not establish EU-independent model
lineage or an adopted sovereign production profile. See
[local quality diagnostics](docs/local-quality.md) and
[reference deployment](docs/deployment.md). New regression and manual-run results
must be bound to their tested revision before replacing the baseline receipt.
