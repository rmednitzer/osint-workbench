# Implementation and verification status

This is a development workbench with bounded implemented profiles. The full
reference platform is not complete. Code establishes behavior; revision-bound
receipts establish tested scope; target requirements and ADRs establish neither.
Use the [documentation map](docs/documentation-map.md) to distinguish current
runbooks, target specifications, decisions and historical evidence.

The [2026-10-19 roadmap alignment review](docs/testing/roadmap-alignment-2026-10-19.md)
accounts for all 58 requirements and 51 full scenarios. It corrects overview
drift and operator-file admission, and adds an initial bounded
[ASVS control assessment](docs/security/control-evidence.md). Full-profile
acceptance remains open; the review is not a replacement runtime receipt.

## Current runtime qualification

Required foundation and signed build evidence covers Ubuntu 24.04/CPython 3.12
and Ubuntu 26.04/CPython 3.14. Python 3.13 remains permitted with optional
weekly/manual compatibility coverage. The manual Python 3.15 probe covers locked
dependency wheels only; the application bound remains `>=3.12,<3.15`.
[ADR-0050](docs/adr/0050-required-lts-and-optional-python-profiles.md) supersedes
the earlier three-profile requirement. Historical receipts retain their tested
profiles and counts; this policy change is not a new runtime acceptance result.

## Current contracts

Core schema **11**, retrieval profile **4**, checkpoint format **2**.
The programme contains 50 ADRs, 58 requirements and 51 full acceptance scenarios.
Native Ubuntu installs use the distro Python in a venv: 24.04/3.12 and
26.04/3.14. Python 3.14 is not the global minimum; see
[runtime support](docs/runtime-support.md#native-ubuntu-installation).
Earlier published SQL resources remain immutable. Legacy checkpoint format 1 is
not silently adopted. The [requirements](docs/assurance/requirements.md) and
[verification matrix](docs/testing/verification-plan.md) retain their full target
scope; passing foundation regressions does not close every scenario.

| Area | Implemented behavior | Material limits and remaining acceptance |
| --- | --- | --- |
| Configuration and storage | Typed external configuration, empty bundled source list, packaged additive migrations, immutable versions/current heads and hashed evidence objects | Single-operator reference; no complete tenancy, physical media integrity or full-host recovery claim |
| Collection | RSS/Atom extraction, public-destination HTTP with DNS pinning/TLS, per-hop redirect checks, framing/byte/deadline limits, due ticks, conditional validators, backoff and bounded Retry-After | No article crawling or ZIP/PDF; specialist formats are limited to the explicit KEV adapter; compressed responses rejected; shared-host quotas and representative Internet/deployment acceptance remain open |
| API acquisition | Opt-in HTTPS GET `bounded-json-pages/1` and [KEV-format catalogue acquisition](docs/kev-acquisition.md), checked systemd/file credential references, fixed bearer/API-key headers and [bounded OAuth client credentials](docs/oauth-acquisition.md), per-page atomic continuation, partial freshness and bounded cross-tick loop detection; [runbook](docs/api-acquisition.md) | Explicit all-existing-uses-permitted/unmetered declarations only; opt-in single-source systemd service/timer; no restricted licensed content, other provider adapters, other OAuth flows/asymmetric client authentication, paid queries or actual provider acceptance |
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
| Deployment | Non-root feed/API collectors, bounded chunk-worker and aggregate-health service/timer templates; explicit group-readable evidence creation option and guarded disposable reference-service harness | Thresholds are operator choices; unsupported downstream jobs remain queued; historical receipts cover named revisions; no complete stack, dashboard/notification routing, backup automation or operational-host acceptance |
| Publication and supply chain | Positive file selection, source/artifact/new-metadata scans, planned-message preflight, locked builds, Python CycloneDX SBOM, reviewed licence/native-file evidence and separate main-push signing | Private exact-value scans stay outside public CI; native/OS/model composition and redistribution clearance remain incomplete; neither scanner success nor signatures establish anonymity or full assurance |

The generic chunk worker handles only `document.accepted`. Enrichment claims only
its explicitly selected local generator or cloud route identity. Other job kinds
remain queued. Character chunks preserve offsets but are not the token-aware
chunks used by the optional retrieval profile.

## Verified baseline and evidence scope

The OAuth service candidate `a567d10a72d3830fde2cffb57e3e0745f1bc4c0a` passed
both LTS service and credential-isolation profiles in run `39170561506`. Its
[receipt](docs/testing/oauth-service-2026-10-19.json) binds source, wheel and
harness/unit hashes to loaded-secret token/resource exchange, denial/backoff,
recovery, non-retention and reader postconditions. Separate-origin TLS and native
SQL cases belong to foundation checks. This does not establish actual provider
contracts, restricted content rights or complete OAuth conformance.

The KEV service candidate `2789f99bf00602b3a81c08d6c9acb20272ec71c7` passed
both LTS service and credential-isolation profiles in run `39166863336`. Its
[receipt](docs/testing/kev-service-2026-10-18.json) binds source, harness/unit
hashes and wheel to synthetic collection, replay, schema refusal and actual
worker/reader acceptance. This is not operational publisher access, full-catalogue
capacity or local-asset applicability evidence. Foundation checks remain separate.

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

The scheduled API candidate `9c03e4eb053998ccd4b5022e81f93941ab1b4f63`
passed the separate Ubuntu 24.04/Python 3.12 and Ubuntu 26.04/Python 3.14 service
jobs in run `39153966588`. Its [service receipt](docs/testing/scheduled-api-service-2026-10-18.json)
binds the wheel and unit/harness hashes to observed authenticated HTTPS,
partial/terminal continuation, accelerated timer, credential failure/replacement,
backoff, recovery and downstream worker/reader outcomes. Its TLS peer is synthetic
and disconnected; no actual provider or operational host was contacted. This
service evidence does not substitute for the candidate's foundation matrix.
The [hardening successor](docs/testing/scheduled-api-hardening-2026-10-18.json)
records both LTS service passes in `39154880281` at
`e3e13af7003ebe31965732e8868ca618838b9e55`, with explicit fixture TLS minimum and
a hash-only synthetic peer verifier. The matching CodeQL disposition is recorded
[individually](docs/testing/codeql-triage-2026-10-18.md#scheduled-api-fixture-successor);
no query/path exclusion was introduced. Older receipt hashes remain historical.


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

The [2026-10-19 lock-maintenance service successor](docs/testing/lock-maintenance-service-2026-10-19.json)
records successful actual service and credential-isolation runs on both LTS distro
interpreters at `237660c0`, with the exact updated dependency lock and unchanged
application wheel. This remains core-service fixture evidence; foundation CI
separately verifies the complete runtime/retrieval profiles.

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
finding or intercept future GitHub UI edits automatically. PR #23 merge
`02685c13` later copied public upstream release-note URLs into Git metadata and
failed the same policy. The [merge-message settings repair](docs/testing/merge-message-settings-2026-10-19.json)
sets blank default bodies while preserving history and the scanner. New
incremental passes exclude these reviewed historical findings; they do not clear
them.

Keep operational sources, hostnames, credentials, prompts, private inventories,
checkpoints and deployment configuration outside Git and public CI. Prototype
code is feature/failure evidence, never a correctness oracle or a public fixture
source. A private checkpoint is not a consumer export; a verified quote is not a
true assertion; an approved adapter is not permission for remote disclosure.
