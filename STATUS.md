# Implementation and verification status

This is a development workbench with bounded implemented profiles. The full
reference platform is not complete. Code establishes behavior; revision-bound
receipts establish tested scope; target requirements and ADRs establish neither.
Use the [documentation map](docs/documentation-map.md) to distinguish current
runbooks, target specifications, decisions and historical evidence.

## Current contracts

Core schema **10**, retrieval profile **4**, checkpoint format **2**.
The programme contains 45 ADRs, 58 requirements and 51 full acceptance scenarios.
Earlier published SQL resources remain immutable. Legacy checkpoint format 1 is
not silently adopted. The [requirements](docs/assurance/requirements.md) and
[verification matrix](docs/testing/verification-plan.md) retain their full target
scope; passing foundation regressions does not close every scenario.

| Area | Implemented behavior | Material limits and remaining acceptance |
| --- | --- | --- |
| Configuration and storage | Typed external configuration, empty bundled source list, packaged additive migrations, immutable versions/current heads and hashed evidence objects | Single-operator reference; no complete tenancy, physical media integrity or full-host recovery claim |
| Collection | RSS/Atom extraction, public-destination HTTP with DNS pinning/TLS, per-hop redirect checks, framing/byte/deadline limits, due ticks, conditional validators, backoff and bounded Retry-After | No article crawling, ZIP/PDF or specialist upstream adapters; compressed responses rejected; shared-host quotas and representative Internet/deployment acceptance remain open |
| Item identity | Changed feed containers retain raw run evidence; unchanged items reuse their current heads and enqueue no new work | No feed-absence deletion or whole-feed atomic replacement; exact old-container replay follows ADR-0040 |
| Jobs | Leases, fencing, bounded retries, renewal/cancellation and atomic character-chunk acceptance | Cancellation revokes result acceptance, not physical computation or incurred remote effects; terminal-job deduplication is not a reset command |
| MCP | Seven read-only stdio tools with strict application schemas, UTF-8 byte-budget pagination, exact reader relation/column checks; MCP SDK 2.3 low-level handlers and per-server tracing opt-out | Source enumeration now uses a results envelope; briefing pages retain full product identity with explicit partial scope; live pages are not snapshots; no remote listener or observed assistant-client compatibility matrix |
| Retrieval | Local ONNX encoder, token-aware retrieval chunks, exact pgvector/RRF, optional ONNX pair reranking, atomic generation activation/rollback, explicit member exclusions and instance-local in-flight query sharing | Excluded members remain lexically searchable; majority-excluded builds fail; no ANN, persistent cache, automatic backfill, adopted pretrained quality or general workspace authorization |
| Local inference | Synthetic ONNX/GGUF execution, Unix-socket generation, literal source/trusted-template token separation and tokenization-policy generator identity; shared cooperative admission, uncertain-work markers and encoder/reranker parent-death binding | Automatic tokenizer suffixes/transformations unsupported; old enrichment kinds stay queued; single-account Linux controls, not a same-UID sandbox or cross-host/GPU scheduler; scheduling overlap and uncertainty remain explicit |
| Enrichment and cited products | Typed extraction proposals, original-text evidence spans, append-only operator review, current accepted assertion reads and evidence-bound cited digests | Review actor is attribution, not separate reviewer authentication; subject/object labels need not occur in the quote; no entailment, richer aliases/merges, diversity or semantic-quality acceptance |
| Domain profiles | Strict offline advisory-observation envelope with independent source, score and date fields | No upstream advisory persistence/applicability engine or implemented regulatory intelligence; catalogue presence does not establish exposure |
| Governed cloud | Explicitly routed/classified compatible chat-completions enrichment, declared provider facts, denial records, Decimal per-currency reservations and unresolved-attempt replay guard | Provider facts are operator declarations; no independent sovereignty verification, live-provider acceptance, native vendor adapters, streaming, batches, silent fallback or separate dispatcher identity |
| Accounting | Immutable evidence-digest-bound operator settlement under separate accounting authority; database transition times and row-lock ordering; Read Committed reservation admission before the route lock | No invoice import, automatic reconciliation or settlement correction workflow; settlement asserts an amount, not verified invoice semantics; same terminal job is not requeued automatically |
| Lifecycle and recovery | Retention/holds/logical retirement, filtered reads, current-policy restore reconciliation, bounded private checkpoint/empty-target restore, reviewed orphan GC and transactional retired-record SQL purge | Purge preserves remote ledger rows; CAS/shared feeds/WAL/backups/provider and published copies are not erased; independent policy custody, larger-corpus and full-host/PITR acceptance remain open |
| Deployment | Non-root collector, bounded chunk-worker and aggregate-health service/timer templates; explicit group-readable evidence creation option and guarded disposable reference-service harness | Thresholds are operator choices; unsupported downstream jobs remain queued; historical receipts cover named revisions; no complete stack, dashboard/notification routing, backup automation or operational-host acceptance |
| Publication and supply chain | Positive file selection, source/artifact/new-metadata scans, planned-message preflight, locked builds, Python CycloneDX SBOM, reviewed licence/native-file evidence and separate main-push signing | Private exact-value scans stay outside public CI; native/OS/model composition and redistribution clearance remain incomplete; neither scanner success nor signatures establish anonymity or full assurance |

The generic chunk worker handles only `document.accepted`. Enrichment claims only
its explicitly selected local generator or cloud route identity. Other job kinds
remain queued. Character chunks preserve offsets but are not the token-aware
chunks used by the optional retrieval profile.

## Verified baseline and evidence scope

The operational-profile candidate `d4a1e64be1e399eb052db13f35ddcf0fc5234b81`
passed **1,203 tests with no skips on each** of Ubuntu 24.04/Python 3.12,
Ubuntu 24.04/Python 3.13 and Ubuntu 26.04/Python 3.14 in foundation run
`39140321685`. CodeQL run `39140320998` completed; two configured-path findings
were individually reviewed and dismissed, without query exclusions. The separate
two-LTS service run `39140321865` passed collection/chunk/health account, custody,
failure/recovery and accelerated timer acceptance using the same wheel. See
[the detailed evidence](docs/testing/operational-acceptance-2026-10-18.md) and
[service receipt](docs/testing/operational-service-2026-10-18.json).
Later changes need their own checks; these results are not a floating current pass.

These are installed-wheel tests against disposable PostgreSQL 18/pgvector,
native HTTP/TLS/Unix transports and authored synthetic ONNX/GGUF fixtures. They
establish execution, authority, consistency and failure contracts within those
fixtures. They do not establish pretrained usefulness, live-provider behavior,
sovereignty, real assistant compatibility, representative performance or complete
E01–E51 acceptance. See [runtime support](docs/runtime-support.md) and
[the verification plan](docs/testing/verification-plan.md) for environment gates.

Older evidence remains deliberately revision-bound:

| Evidence | What it establishes |
| --- | --- |
| [Foundation verification receipt](docs/testing/verification-evidence.json) and [query-coalescing receipt](docs/testing/query-coalescing.json) | Their earlier source, wheel, schema and native regression results; their test counts are historical |
| PR #13 baseline `d01f80ac`, foundation `39133727926`, CodeQL `39133727466` | Earlier 1,031-test baseline; its tested PR head `9fd0920d` passed each profile in `39132871377`; superseded by the bounded operational-profile evidence above |
| [Core-10 service successor](docs/testing/documentation-service-2026-10-18.json) | Both LTS systemd/HTTP/SCRAM/timer/head-reuse fixtures at `ebdbf666`; exact wheel digests retained, no pretrained or operational acceptance |
| [Profile diagnostics](docs/testing/profile-diagnostics.json) and [collector deployment](docs/testing/collector-deployment.json) | Named disposable service/model probes; not acceptance of every later schema or dependency |
| [Local quality observations](docs/local-quality.md) | Six document/eight query pretrained diagnostic calls on public authored cases; lexical and encoder aggregates tied, both failed unsupported-query abstention; no model adoption |
| [Dependency currency](docs/testing/dependency-currency-2026-10-18.json), [tool pins](docs/testing/dependency-tools-2026-10-18.json) and [security settings](docs/testing/security-settings-2026-10-18.json) | Dated reviewed selections and observed settings, not perpetual freshness or conformance |
| [Audit dispositions](docs/testing/audit-remediation-2026-10-18.md) and [CodeQL triage](docs/testing/codeql-triage-2026-10-18.md) | Specific corrected findings and unresolved authority/quality issues; per-alert dispositions are not query exclusions |

## Open acceptance and release limits

The [backlog](docs/implementation-backlog.md) is the canonical unfinished-work
ledger; the [roadmap](ROADMAP.md) groups its delivery scope. Retain local,
cloud, domain and remote profiles even when their implementation is incomplete.
The [architecture](docs/architecture.md), [profile specifications](docs/profiles/)
and [STPA analysis](docs/assurance/stpa.md) distinguish target controls from bounded
implemented refinements. Security references are adopted engineering inputs, not
claims of formal certification or regulatory compliance.

The PR #9 merge message at `e594e949` contains an agent session URL. A full-range
publication scan still reports it; the incremental scan after PR #13 is clean.
Public history has not been rewritten, and content accessibility behind that URL
has not been established. Planned-message checks do not clear the historical
finding or intercept future GitHub UI edits automatically.

Keep operational sources, hostnames, credentials, prompts, private inventories,
checkpoints and deployment configuration outside Git and public CI. Prototype
code is feature/failure evidence, never a correctness oracle or a public fixture
source. A private checkpoint is not a consumer export; a verified quote is not a
true assertion; an approved adapter is not permission for remote disclosure.
