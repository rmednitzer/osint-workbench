> Target specification. See STATUS.md for implemented and verified scope.

# Complete verification programme

Revision 3: E01-E51 remain the complete target acceptance scenarios. Per-scenario
NOT RUN markers mean the full specified scenario has not been closed. Implemented
regressions cover subsets; the revision-bound `verification-evidence.json` and
STATUS.md identify executed evidence. Do not infer either full programme acceptance
or absence of all testing from these target markers. No live paid-provider or
operational-infrastructure acceptance is claimed. Disposable hosted runners,
real local synthetic inference and synthetic HTTPS provider/database fixtures
have been exercised separately.

## Executed subset at the audit baseline

The merged audit baseline is `d01f80ac88da50c9f826b1a15cb18c75bd1db75f`.
[Foundation run 39133727926](https://github.com/rmednitzer/osint-workbench/actions/runs/39133727926)
completed all three required installed/native profiles, and
[CodeQL run 39133727466](https://github.com/rmednitzer/osint-workbench/actions/runs/39133727466)
completed successfully. PR #13's preceding
[run 39132871377](https://github.com/rmednitzer/osint-workbench/actions/runs/39132871377)
reported 1031 passing tests with no skips in each profile. These are distinct
source-bound runs; this documentation audit does not transfer their result to
its own later revision or change the historical JSON receipts.

The executed suite includes seven-tool stdio MCP, native synthetic inference,
SQL migration/recovery/roles, scoped cloud-compatible HTTPS and ledger contracts,
and v3 evidence generation. It does not close the larger scenarios below:
remote MCP, real assistant/vendor interoperability, independent pretrained
semantic quality, batch processing, full export/publisher/host recovery, native
composition/licence clearance and operational deployment remain separate scope.
A successful foundation run also does not run the privileged systemd-service
workflow. Its historical [collector receipt](collector-deployment.json) has a
separate older source/wheel; the
[core-10 successor](documentation-service-2026-10-18.json) records successful
service-only checks on both LTS defaults at `ebdbf666e0f4001dca59ce8760386aae80408d61`.
Neither receipt is foundation CI or full operational deployment acceptance.
See [deployment](../deployment.md) for the fixture boundary.

## Test strata and proof limits

Unit/property/parser tests establish narrow functional boundaries. Integration tests use real disposable PostgreSQL, evidence stores, job workers, actual installed adapters and HTTP fixtures. Full E2E installs built wheel/container artifacts, uses a real MCP client, real local generation/embedding/rerank models and the complete data-to-product path. Provider fixture E2E runs actual client code against a fake server; live-provider verification is separate and pending. GPU-specific claims need actual declared hardware; CPU evidence cannot prove GPU behaviour. Static/source assertions and schema success do not establish semantic quality.

Use synthetic sources, legal/advisory corpora, SBOMs, context and provider responses. No operational data, source URLs or credentials. HTTP test routing belongs only to the isolated harness; do not ship allow-private enforcement bypasses. Test the real installed production SSRF policy separately. Dependencies/models are acquired explicitly and verified before network-isolated test runs. No runtime auto-downloads.

## Profile and workflow coverage

Required combinations: core; core+retrieval; core+local-inference; core+retrieval+enrichment+graph/briefings; vulnerability and regulatory profiles independently and together; cloud-enabled permitted/denied routes; all local profiles with cloud absent; publishing enabled/disabled; mixed-workload recovery. Exercise enabled healthy, intentionally disabled, unconfigured, stale/degraded, unavailable and restored states. All profile-combination cases are explicit test inventory, not an uncontrolled Cartesian explosion.

Canonical full workflow: synthetic source -> raw snapshot -> structured/normalized documents -> chunks -> real local embeddings -> hybrid/reranked query -> enrichment/graph/domain facts -> cited briefing/dossier -> MCP reads -> schema-versioned export -> backup -> isolated restore -> same IDs/evidence and allowed current products. Cloud counterpart routes a classified synthetic packet through the real adapter/fake provider, budget/batch ledger and validated result acceptance, then separately records whether any real provider smoke test ran.

## Quality targets and independent oracles

Freeze development versus held-out cases and accepted metrics before choosing models/prompts. Include English/German text, long sections, Unicode, negation, contradictions, legal state/time, advisory versions, source independence and low-frequency material events. Structured parsers use exact expected records; spans slice original text; retrieval compares exact/labelled relevance; factual statements have manually reviewed support/refutation labels. Model judges are supplementary and labelled.

Hard gates: zero accepted invalid schema/unauthorized effects, zero wrong accepted evidence spans, all critical identifier/domain-state cases correct, no unsupported consequential claims in the accepted synthetic oracle set, no unexpected mandatory skips and no unresolved private-data findings. Recall, extraction coverage/F1, nDCG, citation coverage, abstention and omission targets must be accepted numerically at M0 before model selection. No semantic-quality acceptance while these targets are unresolved. Measure latency/resource/cost with declared workload rather than inventing a production SLO.

## Scenario matrix

### E01: Clean install and complete workflow

Action: Create an empty environment from the locked deployment inputs, install the built wheel, initialize PostgreSQL and import a synthetic feed/document corpus. Run search and evidence reads through a real MCP client.

Oracle / pass condition: Expected fixture IDs/titles and raw/normalized hashes match independent fixture oracles; no source-checkout imports, operational config, GPU or SaaS. Empty source config makes zero outbound source requests.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E02: Replay, updates and concurrency

Action: Ingest an identical source version twice and from concurrent processes, then ingest changed bytes with the same logical document key.

Oracle / pass condition: One snapshot per source/raw version; changed version retained; stable provenance; no lost run outcomes, duplicate accepted rows or integrity errors.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E03: Evidence and export integrity

Action: Check raw and normalized digests with an independent hashing tool; tamper with one object and request it through MCP/export verification.

Oracle / pass condition: Digest correspondence on intact objects; explicit integrity mismatch on tampered data; no verified/read-success label. Round-trip preserves selected IDs and content hashes.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E04: Search semantics and corpus generation

Action: Use a small frozen corpus with exact expected term/identifier matches, ties, no-match queries and a concurrent index refresh.

Oracle / pass condition: Expected IDs/order follow documented lexical rules; no-match differs from outage; each response uses one accepted generation and cites its snapshot IDs.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E05: Freshness and failed collection

Action: Control time, publish no new articles, stop scheduling, fail a fetch and supply missing/future/malformed publisher dates.

Oracle / pass condition: Last attempt and last success differ correctly; configured stale/unknown/disabled/unconfigured states are correct; no fabricated publication date or fresh flag.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E06: Crash consistency and restart

Action: Kill disposable collector processes or inject file/transaction errors before object promotion, before DB commit, after DB commit and during index refresh.

Oracle / pass condition: No dangling accepted references; previous corpus usable; orphan detection explicit; idempotent replay reconciles run identity; DB unavailable returns unavailable rather than empty success.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E07: Real MCP interoperability

Action: Use a real maintained MCP SDK client against the installed stdio server in modern discovery and legacy initialization modes: discover enabled-profile read tools, call every registered tool, paginate, reject disabled-profile tools and shut down. Record the negotiated version per mode and exercise the adapter with its SDK tracing middleware removed.

Oracle / pass condition: Negotiation and schemas validate; registered tools exactly match the versioned capability manifest; no writes/admin/model execution. stdout is protocol-only and shutdown leaves no owned tasks.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E08: Authority and input abuse

Action: Attempt unknown tools, extra fields, arbitrary SQL/path/URL selectors, SQL injection payloads, traversal/symlinks and direct writes using reader credentials.

Oracle / pass condition: Every forbidden action is rejected with no DB/object changes. Reader has no DDL/DML/mutating-function authority, collector credentials or writable evidence mount. Errors expose no private DSN/path/stack.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E09: Network and source privacy

Action: Exercise real bounded fetch code against controlled DNS/redirect fixtures for loopback/private/link-local/metadata/IPv6/mapped addresses, mixed answers, rebinding, proxy env, credential URLs and scheme changes.

Oracle / pass condition: No prohibited destination receives a connection; TLS origin identity remains verified; every hop checked; no source request when unconfigured; MCP cannot fetch; real catalogue is never loaded.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E10: Resource deadlines and cancellation

Action: Use slow DNS, trickle bodies, redirect loops, retryable errors, malformed gzip, expansion bombs, oversized bodies/results and failing DB queries.

Oracle / pass condition: Configured time/byte/concurrency budgets are enforced; decoded and wire limits both work; connections/tasks close; truncation is explicit; retries terminate and failures remain observable.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E11: Evidence-state and attribution semantics

Action: Use intact-but-stale content, usable-but-unreviewed extraction, a short body, conflicting source statements and missing publisher dates.

Oracle / pass condition: Integrity/extraction/freshness states remain independent. Hashes/rank/text length never imply factual verification; no automatic source-authority promotion or synthetic corroboration.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E12: Hostile parsing and instruction content

Action: Supply malicious XML/entities, malformed feed dates/encodings, script/visible prompt instructions, CSV-like formula text and hostile document identifiers.

Oracle / pass condition: No execution, entity resolution, unrequested fetch or path escape; safe supported extraction or explicit error. Text stays untrusted; exports do not turn text into executable spreadsheets/templates.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E13: Backup, restore and migration recovery

Action: Back up an accepted synthetic corpus under an explicit consistent snapshot/quiesce point; restore database and objects onto a fresh deployment. Test missing/mismatched volume and failed migration.

Oracle / pass condition: Every accepted reference/digest verifies; same MCP queries resolve; incompatible restore is rejected. Previous build/backup pair recovers from failure. No operational services involved.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E14: Deployment and package portability

Action: Build wheel/sdist and reference container from approved context; install into a clean environment with no checkout; inspect migrations/entrypoints and process authority.

Oracle / pass condition: Documented install/profile commands succeed with complete packaged migrations; non-root scoped processes, no host-control sockets or implicit model downloads/source defaults; actual tested engine/runtime/hardware and enabled profile recorded.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E15: Bounded concurrent workload

Action: Run concurrent collection and reads over a fixed synthetic corpus and configured limits; cancel clients and terminate dependencies.

Oracle / pass condition: No unbounded queues, deadlocks, task leaks or corruption; overload/failure explicit; timeout defaults enforced. Record workload and measurements; do not claim an unmeasured latency/capacity SLO.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E16: Release supply chain and evidence binding

Action: Audit dependencies/licenses, generate fresh SBOM, run static checks and inspect built artifacts; change one byte after producing receipts.

Oracle / pass condition: All material findings disposed; exact input/artifact hashes recorded; altered candidate fails receipt validation; zero unexpected mandatory-test skips.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E17: Consumer export compatibility

Action: Export selected synthetic records without URL disclosure, verify/import the bundle in an independent fresh installation and query through MCP. Repeat with explicit URL disclosure.

Oracle / pass condition: Default export contains no source URL fields; opt-in profile contains only selected fields; relationship/hash invariants survive; unsupported schema versions fail clearly.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E18: Publication leak gate and canaries

Action: Scan selected files, all introduced reachable history/metadata, unpacked packages, image layers and generated logs/reports. Seed synthetic canaries in every required surface, then scan the real candidate privately.

Oracle / pass condition: Each seeded private-like category blocks release, approved public references pass, no raw secret appears in public receipt, and the real private identifier/source check has zero unresolved findings. Bind to exact bytes.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E19: Acquisition adapter completeness

Action: Exercise each enabled generic/specialist adapter with synthetic pagination, ETag/304, changed/removed entries, duplicate cursors, schema drift, rate limits and source layout changes.

Oracle / pass condition: Expected records and acquisition identities match; no import-time source seed, private defaults or infinite pagination; no-news differs from parse-failed/blocked.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E20: Structured/legal/PDF parser containment

Action: Parse synthetic XML/FORMEX ZIP/PDF, oversized or nested members, XXE, zip-slip, compression bombs, parser timeout and corrupt/unsupported files using actual parser processes.

Oracle / pass condition: Expected articles/sections and source hashes preserved; no external entity network/path write; bounded time/decoded/member limits and explicit partial/failed status.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E21: Embedding/chunk contract and real compute

Action: Run real local query/document encoders over multilingual/long synthetic snapshots; change tokenizer/template/dimension/pooling and supply NaN/incorrect vectors.

Oracle / pass condition: Stable chunk coordinates/hashes and actual vectors; incompatible fingerprints or shapes rejected before writes/query; no silent truncation/model auto-download.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E22: Index generation, filtering and backfill

Action: Compare exact vector oracle to ANN/hybrid under source/workspace filters, new/deleted documents, missing vectors and concurrent generation build/activation.

Oracle / pass condition: No unauthorized candidates; recall and missing-result behaviour meet frozen targets; atomic complete-generation switch, cache invalidation and rollback preserve usable old corpus.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E23: Encoder/reranker contracts and cache isolation

Action: Use actual reference models and deliberate malformed/mismatched ranker outputs; repeat queries across filters/workspaces/model generations with coalesced waiters.

Oracle / pass condition: Candidate IDs/order/finite scores validated; no cross-scope/generation cache reuse; timeout waiter does not corrupt owner; real local outputs recorded.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E24: Retrieval quality gate

Action: Evaluate frozen held-out exact-ID/paraphrase/English/German/long-section/negation/duplicate queries with human/structured relevance labels and fixed baseline.

Oracle / pass condition: Predeclared quality targets/critical-case invariants pass; filtered ANN checked against exact; latency/resource measurements labelled by workload; no test-set model selection.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E25: Durable enrichment DAG and restart

Action: Run extraction/classification/correlation/summary jobs from real installed workers/local models; crash at lease, inference, validation, accepted commit and downstream enqueue boundaries.

Oracle / pass condition: Committed inputs produce one accepted effect per dedup identity; retry/checkpoint/outbox state correct; no duplicate accepted reports or missing terminal feedback.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E26: Fencing, cancellation and late result

Action: Expire/reassign a job while the first worker runs; cancel during model computation/acceptance; reconnect after worker/network failure.

Oracle / pass condition: Stale fencing tokens cannot commit; cancellation state reconciled with actual worker outcome; partial/unknown work not relabelled successful or blindly replayed.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E27: Evidence support, Unicode and calibration limits

Action: Use the confirmed Straße/abc case plus case expansion, combining characters, multilingual whitespace, negation, misleading quotations and fabricated citations in deterministic/model proposals.

Oracle / pass condition: Every accepted span slices exact named source coordinates; unsupported propositions rejected/quarantined/abstained; no hard-coded score presented as probability or factual verification.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E28: Graph assertions, contradictions and alias reversal

Action: Project structured advisories and model proposals; test mentions-versus-affects, homonyms, competing sources, supersession, ontology change and mistaken merge reversal.

Oracle / pass condition: Source/ontology/lifecycle preserved; no unsupported strong edge promotion; contradictions remain visible; merge reversal and reprocessing restore expected IDs/edges.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E29: Briefing quality and diversity

Action: Generate briefings with real local inference from frozen synthetic multi-source/syndicated/conflicting/stale material, including important low-frequency events.

Oracle / pass condition: Consequential claims have supporting evidence and correct dates/qualifiers; omissions/citation precision/diversity meet frozen targets; unsupported output abstains and fallback is labelled.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E30: Context, deadlines and product lineage

Action: Create explicit synthetic workspace decisions/threads/deadlines; retire context, change evidence and render versioned briefing/dossier products through MCP.

Oracle / pass condition: Only explicitly allowed current context used; actor/sensitivity/time/lineage preserved; old products superseded visibly and no private personal/fleet context auto-appended.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E31: Vulnerability upstream facts and revisions

Action: Process synthetic CVE/vendor/OS/KEV/EPSS/OSV responses with rejected records, changed CVSS/ranges, stale scores and contradictory advisories.

Oracle / pass condition: Version/date/source fields and conflict state preserved; no overwritten exploitation claim or invented score; downstream re-evaluation tied to changed evidence.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

The [KEV projection](../kev-advisory-projection.md) adds bounded synthetic
regressions in `tests/test_kev_projection.py` and the existing native TLS acquisition
case: verified stored evidence, exact raw mapping, Unicode byte spans, explicit
attribution and reader/lifecycle refusal. These do not complete the multi-format,
retraction/conflict or downstream re-evaluation scenario above.

### E32: Applicability and policy-based priority

Action: Evaluate package/SBOM fixtures with ecosystem versions, ambiguous CPE/product names, absent inventory and distinct exposure/prerequisite states.

Oracle / pass condition: Applicability is proven/matched/unknown per explicit evidence; no target affected assumption or universal patch deadlines from CVSS/EPSS alone; configured policy rationale visible.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E33: Regulatory semantics and transitions

Action: Process synthetic EU/national binding acts, proposals, guidance, corrigenda, consolidations, languages and procedure-family events with distinct force/application/transposition dates.

Oracle / pass condition: Instrument/article/version/jurisdiction and legal status correct; no proposal-as-law or generic compliance claim; uncertain mappings stay review-pending.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E34: Real local model supply chain and upgrade

Action: Acquire reviewed small reference models explicitly in the harness, verify hashes/licenses/code, run real generation/embedding/rerank and change a model/template manifest.

Oracle / pass condition: Actual role/capability outputs validated; no hidden downloads or unaudited custom code; drift/mismatch blocked; old model/index profile restores. Record actual hardware instead of assuming GPU support.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E35: Local protocol, tools, streams and incomplete output

Action: Exercise actual local server with schema/tool requests, serial/parallel capability differences, malformed output, refusal/length limits, fragmented streams and unavailable models.

Oracle / pass condition: Native declared capabilities match probes; unknown tools/output not accepted; incomplete state explicit; stream cancellation closes owned work and lexical/read access remains available.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E36: Shared model resource and hard admission

Action: Compete interactive search/encoding/rerank/generation and batch work; cause owned worker OOM/hang, unavailable quota storage and cancellation races.

Oracle / pass condition: Budgets/queues/fairness enforced; only owned processes affected; no replacement before confirmed reaping; hard quota failure denies new work; no starvation beyond declared policy.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E37: Cloud egress and native adapter contracts

Action: Run installed OpenAI/Anthropic/compatible adapters against synthetic protocol servers with capability/access/refusal/usage differences; test local-only and sovereignty/data-policy denial.

Oracle / pass condition: Actual adapter code handles native semantics; zero provider egress when local-only/unapproved; route/packet/reservation persisted; no silent cloud/cross-provider escalation. This is contract E2E, not live-provider proof.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E38: Ambiguous remote outcomes and streaming usage

Action: Drop responses after accepted requests, interrupt streams with partial usage, send 429/5xx/auth failures, missing/invalid usage and provider-specific cache/reasoning categories.

Oracle / pass condition: Unknown charge/work state retained; no blind duplicate paid retry; explicit refusal/incomplete/error and usage categories; reservation reconciliation never invents zero cost.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E39: Derived invalidation and restored context

Action: Change snapshot/chunk/model/prompt/policy/workspace state, tombstone context, restore an older backup and query retrieval/graph/model packets.

Oracle / pass condition: All dependent caches/index/assertion/product/job states invalidate or supersede; restored deletion policy applied before serving; no retired/private context leaks into fresh packets.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E40: Domain/source partial and semantic drift

Action: Make official-family member fetches partial, invalidate corroboration after extraction version changes, change specialist layouts and provide conflicting effective dates.

Oracle / pass condition: No-news and incomplete source coverage differ; review-pending/unknown retained; old corroboration cannot promote new text; adapters disclose versioned parse failures.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E41: Model/provider catalogue and route promotion

Action: Discover changed aliases, deprecated/unapproved models, stale pricebook/policy and failed entitlement probes; try activation without evaluation evidence.

Oracle / pass condition: Discovery never changes active route; capability/quality/license/sovereignty/budget gate required; fallback cannot widen permissions; identity/reproducibility limits visible.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E42: Budget/accounting concurrency and currency

Action: Reserve concurrently across workers/batches, crash between dispatch/reconcile, supply inconsistent usage/pricebook/invoice fixtures and mixed currencies.

Oracle / pass condition: Atomic hard caps and pending outcomes; Decimal per-currency totals; estimates/observed/billed distinct; no fabricated conversion/refund/unknown-as-zero.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E43: Batch lifecycle and import idempotency

Action: Submit to fake providers, restart before receiving ID, poll partial/expired/cancelled/late batches and import duplicate/missing/malformed custom IDs.

Oracle / pass condition: Logical/remote IDs retained or outcome-unknown; accepted result import idempotent; invalid rows quarantined; cancellation not treated as zero spend/data erasure.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E44: Prompt injection and authority across full profiles

Action: Place hostile instructions in source body/metadata, retrieved passages, graph/context, model output and tool arguments; request policies/secrets/unauthorized jobs/egress through MCP/analyst.

Oracle / pass condition: No policy/tool/credential/host authority escalation or unintended external effects; schema/evidence postconditions enforced. A model obeying hostile prose without extra effects is tracked as quality failure, not hidden as security success.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E45: Full database/migration/recovery workload

Action: Run mixed acquisition/index/enrichment/reader/accounting jobs during upgrades and controlled storage/DB faults, then restore matched checkpoint on a fresh installation.

Oracle / pass condition: Actual grants/index/query plans reviewed; no partial incompatible migration served; references/jobs/reservations consistent; restore and previous-version recovery validated.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E46: Observability and privacy under failure

Action: Trigger stale feeds, parser/model/provider/index/lease/backup/accounting failures and inspect metrics/dashboard/status/support bundle from installed stack.

Oracle / pass condition: Right state/alert reached; bounded labels/no prompts/URLs/DSNs/private identifiers; liveness never substitutes for source freshness or profile readiness.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E47: Optional publisher and reconciliation

Action: Publish synthetic approved products to a disposable local fake Git remote; disable configuration, change staged bundle, fail receipt storage and repeat reconciliation.

Oracle / pass condition: Disabled makes no outbound effects; exact schema/disclosure/hash policy required; immutable receipt/import identities and idempotent reconciliation; no private data/destination default.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E48: Retention, holds and deletion recovery

Action: Create evidence/derived/context/accounting/report records with different retention/holds; dry-run/apply scoped GC and restore backup with tombstones.

Oracle / pass condition: No held/referenced evidence purged; derivative/cache/job deletion propagates; restore respects tombstones; immutable published/provider/backup deletion limits stated accurately.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E49: Authenticated remote MCP

Action: Run actual installed Streamable HTTP transport behind disposable TLS/authorization services; perform discovery/token-validation/reads and vary issuer/audience/expiry/scopes/origin.

Oracle / pass condition: Only authorized scoped reads succeed; no unauthenticated listener/default bypass or token passthrough; malformed/expired/wrong-resource tokens denied. Maintained components, no custom cryptography.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E50: Remote session, principal and revocation boundaries

Action: Attempt session reuse across principals/workspaces, reconnect after expiration/revocation, overload requests and disable the remote profile.

Oracle / pass condition: No cross-principal data/session access, bounded resources and explicit errors; remote listener/session authority removed when disabled while stdio still works; logs redact tokens and claims with private identifiers.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

### E51: Client and transport compatibility

Action: Run the same fixture read/search/domain/product cases over stdio and remote transport using real independently implemented clients; perform an operator-selected actual assistant smoke test when available.

Oracle / pass condition: Same authorized application semantics and stable schemas, documented negotiated versions and unsupported capabilities; actual assistant test unavailable remains pending rather than assumed from SDK success.

Evidence: revision/profile/fixture/tool identity, assertions, bounded sanitized logs and relevant request/job/model/artifact digests. Status: NOT RUN.

## CI and release evidence

Run fast lint/type/unit/property/dependency/secret checks first, then schema/permission/adapter integrations, then installed-artifact core/full-profile E2E, real local-model quality/resource suites and finally exact release/privacy gates. Maintain local commands for every step; CI has no dependency on private fleet runners. Resource-heavy profiles can run on trusted isolated runners with no private mounts or untrusted PR credentials. Missing hardware or live provider access produces explicit pending evidence; it cannot be silently skipped and called full verification.

Each receipt records candidate commit/tree/lock/wheel/image, profile configuration schema/version, public synthetic fixture/model/prompt identities, tested OS/engine/hardware versions, UTC run bounds, all cases/pass/fail/skip counts, metrics/targets, scanner dispositions and residuals. Keep private identifier mappings/denylists/matched lines out of public receipts. Any changed relevant bytes/config/model identity invalidates the receipt.

Publication requires the accepted feature/verification status matrix. Contract-tested cloud adapters may be described only as such until separately authorized real synthetic smoke tests verify selected endpoints/models. Full programme closure cannot conceal outstanding required hardware/live-provider tests; record them with exact next checks and scope. No real cloud request is made merely to complete a planning task.
