# Implementation and verification status

This file distinguishes target design from shipped code. No profile may be called
complete merely because its design documents or interfaces exist.

| Area | Current implementation | Verification boundary |
| --- | --- | --- |
| Configuration/package | Typed JSON, empty sources, src layout, packaged migrations | Installed-wheel CI covers retained core migrations and active profile upgrade state; core7/profile3 upgrade, purge and recovery cases passed in the named receipt |
| Evidence/core storage | Hashed immutable objects, PostgreSQL records/version heads | Local object tests; native PostgreSQL tests in CI |
| Jobs | Bounded retries, attempt events, cancellation, renewal and atomic chunk worker | PostgreSQL failure/concurrency tests; distributed/remote effects remain pending |
| Collection | RSS/Atom extraction, bounded public HTTP transport and durable due/validator state | Native HTTP sockets, parser, due/304/backoff, crash/replay and recovery tests passed. Full adversarial HTTP coverage remains pending |
| MCP | Seven stdio reads with strict schemas, reader checks and bounded errors | Real SDK client against PostgreSQL in CI |
| Retrieval | Local ONNX embeddings, token-aware chunks, exact pgvector/RRF and generation activation/rollback | Synthetic numerical ONNX and native database/MCP tests, including actual pair scoring; frozen offline scorer/local diagnostic added; pretrained semantic acceptance, ANN, automatic backfill and caches pending |
| Local inference | CPU embedding/rerank runtimes, native Unix-socket generation and durable shared admission | Actual synthetic ONNX/GGUF execution and Unix transport/crash tests in CI; no GPU, pretrained quality or complete cross-host scheduler |
| Enrichment/graph/briefings | Durable typed proposals, evidence spans, operator reviews and cited assertion digests | PostgreSQL/MCP proposal, review, withdrawal and cited-digest tests passed; pretrained semantic acceptance, aliases/merge and diversity pending |
| Vulnerability/regulatory profiles | Offline advisory observation envelope; broader domain specifications | Authored strict-contract tests; no upstream adapters or applicability verification yet |
| Cloud APIs/accounting/batches | Target specification | No credential access, native adapters, remote requests or spending |
| Remote MCP | Target authentication design | No HTTP listener or remote client compatibility claim |
| Export/recovery/retention | Bounded private checkpoint, empty-target restore, operator retention/holds/logical tombstones and mandatory current-policy reconciliation | Native SQL-reader, job/fence, inference, collector and restored-policy regressions passed in installed-wheel CI. Reviewed orphan-object GC and transactional retired-record SQL purge passed native failure/restart, recovery and scoped-role tests. Full record erasure, legacy format-1 adoption, public export, publisher and full-host/PITR remain pending |
| Publication controls | Positive file selection and source/artifact scanning | File/archive checks plus bounded new-commit metadata scanning; private exact-value checks run outside public CI and do not establish anonymity |

Core schema v7 and retrieval-profile v3 are additive; earlier published migrations
remain byte-identical. Checkpoint format 2 requires separate policy receipts;
legacy format-1 restore/adoption is not silently accepted. Job cancellation
revokes acceptance authority; it does not prove a running computation has stopped.
The core worker processes `document.accepted`; the explicit enrichment worker claims
only its configured generator identity. Other job kinds remain queued.
Character chunks preserve offsets but are not token-aware model input.

The query-coalescing installed-wheel receipt records 645 passing tests with no skips,
including retained-state migration, direct SQL/MCP suppression, native retrieval,
concurrency and policy-gated isolated recovery. See
[the coalescing receipt](docs/testing/query-coalescing.json) and
[the earlier revision-bound receipt](docs/testing/verification-evidence.json). Synthetic
models establish execution contracts, not pretrained semantic quality.

The full programme covers 28 capability areas, 38 ADRs, 58 requirements and 51
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
[reference deployment](docs/deployment.md). Native regression evidence is bound to the tested revision in the verification
receipt; manual profile results are recorded separately.

The explicit pretrained diagnostic completed on a disposable runner: six document
and eight query calls, with the frozen public inputs unchanged. Encoder and lexical
baseline had equal aggregate relevance metrics on these eight authored cases;
both failed unsupported-query abstention. The installed core service also passed
its bounded non-root sandbox and accelerated timeout/child-stop probes. See
[separate profile receipts and preserved observations](docs/testing/profile-diagnostics.json).
Neither result closes semantic-quality adoption or operational deployment acceptance.

Collector authority adds a dedicated column-scoped SQL group and required
`OW_COLLECTOR_DSN` for nonempty CLI collection. Startup checks effective grants,
reachable/delegating roles, object ownership, row security, exact migration
history and the fixed outbox kind before store creation or HTTP dispatch.
Writer credentials remain separate and are not a collection fallback. Reader
credentials cannot carry a settable collector role. This scopes process authority;
it does not establish per-source tenancy or filesystem evidence confidentiality.
The native migration/role/recovery cases passed in the named installed-wheel
receipt. The database-backed reference service also passed its disabled-source
SQL and unsafe-identity probes in [a separate receipt](docs/testing/collector-deployment.json).
The enabled-source extension passed actual service and accelerated timer acceptance
against a disconnected synthetic HTTP fixture, including conditional 304, 503
backoff, no-dispatch while not due, immutable changed versions and matching
CAS/outbox records. The manual receipt records the installed wheel digest,
Unix-socket SCRAM negative control, service UID and owned cleanup. Internet DNS,
TLS, production cadence and operational deployment acceptance remain open.

The bounded per-source Retry-After profile handles final 429/503 advice using the
database clock, preserves ordinary backoff and failed-manual reservations, and
reports malformed hints, seven-day clamping and unconfirmed state persistence
explicitly. It adds no schema migration or worker sleep. Native scheduling/fault
cases and the actual service's 120 s delay/no-dispatch probe passed in the named
revision receipts; redirect
delays, shared-host quotas, trustworthy clocks and longer server minima remain
outside this profile.

Transport assurance adds native TLS trust/hostname/SNI and deadline cases plus
resolver-process/pinning tests. Fixes use the pinned HTTP library's actual error
families, reject explicit port zero and bound complete resolver IPC with typed
JSON, an absolute receive deadline and observed child/thread cleanup. No runtime
TLS verification bypass or system trust-store change is introduced. All 38 new
cases passed in the revision-bound native receipt; normal JSON resolver use also
passed the separate hardened HTTP service receipt. Public
DNS/PKI, revocation and operational TLS acceptance remain outside these fixtures.

The opt-in offline advisory envelope adds strict versioned CVE-linked observations,
independent publisher/evidence attribution, separate dates and bounded redacted
JSON parsing. It preserves conflicting score/exploitation observations without
inferring exposure or remediation. Acquisition, storage, applicability and full
vulnerability-profile acceptance remain pending; see [the bounded contract](docs/advisory-records.md).
The installed-wheel run passed all 147 advisory cases and the retained native
suite in the named verification receipt. No upstream interoperability or semantic
intelligence-quality acceptance follows from these authored contract fixtures.

Retired-record SQL purge adds a private plan/apply operator command, separately
scoped purge credentials and an atomic durable lifecycle decision. It removes
known SQL derivatives, preserves shared/held dependencies and refuses historical
restore content covered by current purge policy. CAS, feeds, backups, WAL and media
erasure remain outside its scope; [the operator procedure](docs/retired-record-purge.md)
describes irreversible effects and retrieval rebuild requirements. All 44 additional purge, race and compatibility cases passed in the named installed-wheel receipt; the current wheel also passed the separate synthetic collector-service run.

Audit remediation adds a store-root inode barrier retained through evidence
acceptance and connection cleanup, independent of database backend liveness.
The installed-wheel receipt includes actual GC backend termination and process
kills with subsequent writer/CAS verification. Data-only feed parsing, typed URL
and UTF-8 packet admission, bounded numeric address fallback and transient
contention retry also passed. Isolated workflow builds enforce a frozen hashed
backend closure; runtime dependencies and published SQL migrations are unchanged.
See [scope, acceptance and open audit dispositions](docs/testing/audit-remediation.md).
These checks do not close the wider semantic, cloud, deployment or erasure roadmap.

Bounded instance-scoped in-flight query sharing preserves one verified native
embedding computation for identical overlapping query packets. Distinct contracts,
waiters, failures and fork ownership are explicit; completed results are not cached.
All 15 additional regressions and the retained native suite passed in the named
645-test receipt. This does not close persistent caches, incremental backfill,
fair cross-process inference scheduling or pretrained semantic-quality acceptance.

Repository maintenance adds canonical AGENTS guidance with native Claude/Copilot
entry points, offline Markdown/link/action checks, strict Renovate validation,
bounded CI and weekly/manual locked-runtime advisory auditing. The
[maintenance policy](docs/repository-maintenance.md) and
[dated settings receipt](docs/testing/repository-settings.json) distinguish selected
configuration from observed API state. The added tooling does not establish all
secure-development, licence, SBOM, provenance or full release gates. Exact current
source/test results remain bound to their CI revision rather than a global count.

Runtime compatibility now declares standard CPython 3.12–3.14, with required
installed/native CI profiles for Ubuntu 24.04/3.12, 24.04/3.13 and 26.04/3.14.
Timestamp admission explicitly bounds clock and offset components; synthetic TLS
fixtures retain strict verification with conforming CA extensions. These controls
and the separate two-LTS service diagnostic are defined in
[runtime support](docs/runtime-support.md) and
[ADR-0035](docs/adr/0035-python-ubuntu-runtime-support.md). Passing results remain
revision-bound; these additions do not relabel earlier receipts or establish
operational deployment, GPU or pretrained quality acceptance.

Publication maintenance adds bounded new-commit metadata checks, an initial four-module
type gate and application-source security lint with reviewed line-level exceptions.
CI retains the tested wheel/sdist and source-bound integrity/inventory receipts for
30 days after successful native tests and publication scans. Main-push provenance
uses a separate signing job that executes no repository code. The installed Python
inventory is not a standards-conformant SBOM or a legal licence disposition. See
[publication privacy](docs/publication-privacy.md), [build evidence](docs/build-evidence.md)
and [ADR-0036](docs/adr/0036-publication-security-evidence.md). Exact successful
CI/signature results must be inspected for the particular revision; configuration
alone is not a receipt. CodeQL and available hosted security settings are recorded
separately in the dated security-settings receipt.

Review of the initial CodeQL findings also hardens operator model-manifest reads:
nonblocking no-follow opens reject nonregular files before reading, enforce the
64 KiB bound before and after the read, and return sanitized errors. Actual CLI
FIFO/symlink/oversize and post-stat growth regressions cover this failure boundary.
This does not turn operator-selected filesystem paths into an untrusted-user
sandbox; trusted parent directories remain required.

Inference-marker hardening anchors host-local admission and receipt operations to
validated directory descriptors, refuses unsafe custody and substituted receipts,
and retains uncertain reservations when prior-process liveness cannot be proved.
This remains cooperative single-account Linux admission, not a same-UID sandbox
or cross-host scheduler; see [marker safety](docs/inference-marker-safety.md).
The successor evidence pipeline generates a strict CycloneDX 1.7 Python-profile
SBOM and checks exact installed licence metadata/text against reviewed policy.
The v2 receipt binds both reports; protected-main signing includes their bytes.
Native/OS/model composition remains incomplete, and missing wheel notices and
bundled native redistribution obligations remain unresolved. See
[SBOM scope](docs/sbom.md), [licence dispositions](docs/security/dependency-licences.md)
and [ADR-0037](docs/adr/0037-inference-custody-python-sbom.md). Configuration and
local focused tests do not replace revision-bound installed/native CI evidence.

Native supply-chain evidence adds exact reviewed identities for recorded ELF files
in the supported runtime wheels, plus parser-derived ELF headers and declared
dynamic library names. The v3 receipt binds that report and a separate supplement
containing the two reviewed upstream licence texts missing from Flatbuffers and
tokenizers wheels. The Python SBOM remains incomplete: this does not identify all
statically linked components, resolve loader state, inspect unrecorded files,
clear redistribution obligations or cover OS/model/test-server composition.
See [native inventory](docs/native-inventory.md),
[notice scope](docs/security/supplementary-notices.md) and
[ADR-0038](docs/adr/0038-native-file-evidence-notices.md). Exact installed/native
and signature results remain specific to the tested revision.
