> Target specification. See STATUS.md for implemented and verified scope.

# Bounded STPA analysis

## Purpose, boundary and method

Analyze loss of privacy, evidence integrity, service utility and operator trust during extraction, operation and publication. This is a proposed system-level analysis for an information-processing reference implementation, not a physical safety certification or a quantitative risk assessment. Method reference: Leveson and Thomas, STPA Handbook, March 2018, chapters 2-3 [S1](../references.md#s1). Complement it with STRIDE threats at trust boundaries rather than treating STPA as a substitute for code security review.

Inside the boundary: maintainer/release decisions, extraction and build process, collector, storage/index, application read services, MCP adapter and operator feedback. Outside: source publishers, package registries, hosting provider and the selected AI client/model. Their effects still enter the analysis as external inputs and disclosure recipients.

## Losses, hazardous states and system constraints

| Loss | Unacceptable outcome |
| --- | --- |
| L1 | Private identifiers, source selection, credentials or personal/operational information are disclosed |
| L2 | A consumer makes a consequential decision from incorrectly attributed, corrupted, incomplete or stale information presented without its limitations |
| L3 | The extracted project damages or exposes the original environment or another reachable system |
| L4 | Accepted evidence is lost, unrecoverable or silently changed |
| L5 | Users cannot establish what was tested or reproduce the supported workflow |

| Hazard | Contextual system state | Losses | Constraint |
| --- | --- | --- | --- |
| H1 | Public artifacts or returned diagnostics contain information outside the intended disclosure scope | L1,L3 | SC1: constrain inputs and all publication/output surfaces; verify exact bytes before disclosure |
| H2 | Retrieved material appears usable while provenance, integrity, extraction or freshness is missing, wrong or concealed | L2,L5 | SC2: preserve independent evidence states and report unknown/degraded conditions |
| H3 | Untrusted source content or an MCP request can exercise acquisition, write or administrative authority outside its scope | L1,L3,L4 | SC3: enforce process, network, path and database authority boundaries |
| H4 | Searchable accepted records do not correspond to recoverable immutable evidence versions | L2,L4 | SC4: coordinate object and metadata commits, reconcile and test restore |
| H5 | Users or release automation treat missing, stale or unrelated test evidence as successful validation | L2,L5 | SC5: bind complete acceptance evidence to the candidate revision and artifacts |
| H6 | Normal operator work depends on hidden private services or uncontrolled retries/resources | L3,L5 | SC6: isolate deployment and bound work; expose non-execution and failure |

## Control structure and feedback

| Controller | Controlled process and control actions | Required process model / feedback |
| --- | --- | --- |
| Maintainer | CA1 approve candidate inclusion; CA2 authorize exact public release | File/data provenance, disclosure class, license dispositions, scan receipt, test status, artifact digests |
| Collector / scheduler | CA3 start acquisition; CA4 accept snapshot/document; CA5 issue retry/cancel | Source config generation, resolved destination, deadlines, run ownership, object/transaction outcome |
| Read service / MCP | CA6 return evidence; CA7 report status | Caller/process authority, record/object identity, index generation, last attempt/success, freshness policy, result limits |
| Operator / retention tool | CA8 initiate restore/migration/purge | Backup identity, reachability, consistency manifest, target environment, recovery checks |
| CI / release verifier | CA9 mark acceptance satisfied | Full test inventory, unexpected skips, tested artifact hash, private/public scan receipts, residual findings |

The maintainer receives status and manifests before release. The operator receives attempt/success/failure and non-execution feedback from collection and recovery. MCP returns corpus and evidence state to the client. Missing feedback is never synthesized as success.

## Unsafe control actions

For every action, consider not provided (N), provided unsafely (P), wrong timing/order (T), and excessive/insufficient duration (D). These are discrete commands; D is not applicable to the command itself. Continuing a fetch is governed by its wall deadline and cancel command, not described as a START command lasting too long. N cases that only delay an optional public release are not hazards by themselves.

| UCA | Action/category and hazardous context | Hazard | Derived control constraint |
| --- | --- | --- | --- |
| U1 | CA1/P: include a candidate whose dependency imports private runtime state or operational configuration | H1,H3,H6 | C1: dependency closure must contain only reviewed public code and synthetic inputs |
| U2 | CA2/P: release an artifact containing private data or unreviewed author/build metadata | H1 | C2: scan and review every outgoing surface, including commit author fields |
| U3 | CA2/T: release after source/artifacts changed since the privacy/test receipts were generated | H1,H5 | C3: bind approvals and receipts to immutable commit/tree/artifact digests |
| U4 | CA3/P: start acquisition after a redirect/DNS change targets a prohibited address or scheme | H3,H6 | C4: validate every hop and connect to validated pinned addresses while preserving TLS identity |
| U5 | CA3/N or T: omit/delay a due collection but leave old content labelled fresh | H2 | C5: freshness follows successful acquisition timestamps and configured intervals, not process liveness |
| U6 | CA4/P or T: accept metadata before the referenced object is durable or after an extraction failure | H2,H4 | C6: accepted searchable records require durable referenced evidence; partial extraction is explicit |
| U7 | CA5/N or T: fail to cancel exhausted acquisition/retries, allowing bounded workloads to monopolize resources | H6 | C7: enforce total deadlines, retry budgets and cancellation with observed termination |
| U8 | CA6/P: return arbitrary paths, private source URLs, credentials or write capabilities in response to client/content input | H1,H3 | C8: typed ID-only reads, redacted defaults, reader-only grants and bounded output |
| U9 | CA6/P: present a hash, ranking score or text-length gate as factual verification | H2 | C9: separate integrity, extraction, freshness and review semantics |
| U10 | CA7/N or T: omit or delay failure feedback while results appear current and complete | H2,H6 | C10: distinguish empty, stale, degraded, unavailable and unconfigured states in all interfaces |
| U11 | CA8/P or T: purge referenced objects, restore mismatched volumes or migrate without a tested recovery pair | H4 | C11: verify backup/object manifest and target isolation; purge is manual and reachability-based |
| U12 | CA9/P: accept mock-only, skipped, stale or different-build tests as release evidence | H5 | C12: mandatory installed-artifact E2E tests, zero unexpected skips and version-bound receipts |

CA1/N is not hazardous for excluded functionality; N can become hazardous if a necessary security dependency is omitted while release still proceeds (U1/U12). CA2/N delays publication and is not itself a scoped loss. CA4/N must preserve previous accepted versions and report acquisition failure (U10). CA6/N must return an explicit unavailable/error response rather than hang or fabricate an empty corpus (U10). CA8/N blocks upgrade until recovery evidence exists; it must not trigger an automatic destructive workaround. CA9/N blocks release; treating its absence as success is U12. Re-evaluate D if a later design introduces sustained authority signals or long-lived remote sessions.

## Causal scenarios and implementation allocation

| Scenario | Causal path and alternative to test | Links | Required mitigation / evidence |
| --- | --- | --- | --- |
| S01 | A harmless-looking parser imports a helper that seeds real feed URLs on import. Ordinary .gitignore scans miss the dependency. | U1,U2; C1,C2 | Import graph plus runtime config tests; E01 and E18 show no hidden source selection/egress |
| S02 | A scanned wheel is rebuilt after review; a build path, email or cached fixture enters the new archive. | U2,U3; C2,C3 | Immutable build once, scan extracted outputs and bind hashes; E16/E18 |
| S03 | Valid public DNS is replaced by a private address or a redirect chain changes scheme. A preflight-only validator trusts the first result. | U4; C4 | Real fetch-path DNS pinning, per-hop validation and wire-level destination assertion; E09 |
| S04 | Database commit succeeds after a file rename failed; alternatively an object is written but the DB commit fails. | U6,U11; C6,C11 | Failure injection at both boundaries; reject dangling accepted metadata, detect orphan objects; E06/E13 |
| S05 | A scheduled fetch stops running; an unchanged article or an embedding cache makes the dashboard appear healthy. | U5,U10; C5,C10 | Fake clock and failed scheduler/acquisition scenarios; E05/E10 |
| S06 | Hostile text tells the assistant to invoke a tool or export credentials; sanitized HTML still contains the instruction in visible prose. | U8,U9; C8,C9 | Treat all retrieved text as data; no server-side execution or authority escalation; E08/E12. External model obedience remains outside the guarantee. |
| S07 | A restored database points to a different-generation evidence volume; smoke search succeeds because it reads indexed text only. | U11; C11 | Restore fresh installation and verify every referenced digest, then retrieve through MCP; E13 |
| S08 | Integration tests are skipped by default but CI is green. A source checkout also hides missing packaged migrations. | U12; C12 | Installed wheel, full test inventory, fail on unexpected skips, clean-room install; E01/E14/E16 |
| S09 | Source read failure triggers retries that amplify an outage, or cancellation stops waiting but leaves DNS/socket work active. | U7,U10; C7,C10 | Request counts, elapsed deadline and active-task/socket checks; E10/E15 |
| S10 | Two collectors ingest the same version while a reindex replaces the corpus; one run loses the other's work. | U6,U10; C6,C10 | Concurrent-run and generation consistency tests; E02/E04/E06 |

## Coverage and residual uncertainty

This covers the complete proposed profile boundary and publication lifecycle. It does not prove completeness, source truth, independent publisher corroboration, hostile model resistance or multi-tenant isolation. The remote transport profile is included under ADR-0017; future unregistered adapters require a new authority review. The ML/claims/cloud/lifecycle extensions below are part of this revision, not deferred scope. Stop release if a safety/security constraint lacks implementation allocation or mandatory verification evidence. A second human review of the model is recommended where available, but no independent human review or formal completeness assessment is established by this document.


## Revision 2: full inference, enrichment and cloud control model

Additional loss L6: unauthorized external processing, uncontrolled financial/resource consumption or irreconcilable remote operations. Additional hazards: H7, classified data leaves the allowed provider/jurisdiction boundary; H8, derived assertions/briefings or incompatible model/index generations are served as supported current evidence; H9, model/provider work continues without valid ownership/budget or cannot be reconciled. H7 maps L1/L3/L6; H8 maps L2/L4/L5; H9 maps L3/L4/L5/L6.

SC7: remote dispatch, model activation and budgets require an explicit durable policy/identity/reservation decision and reconciled outcomes. SC8: every derived product and retrieval generation must remain tied to compatible evidence/model/prompt/schema identity with reversible lifecycle and visible limitations.

Additional controllers: job coordinator (CA10 lease/fence/cancel/accept output); model scheduler (CA11 admit/load/drain/unload/terminate owned worker); policy router (CA12 select and dispatch route/fallback); budget ledger (CA13 reserve/reconcile/release); model registry (CA14 activate a generation/route); enrichment validator (CA15 accept/promote/retract assertions/report); batch coordinator (CA16 submit/poll/cancel/import); lifecycle controller (CA17 hold/tombstone/purge/reapply deletion after restore).

Feedback required: lease/fencing token and checkpoint; real worker PID/ownership/termination; actual model/embedding-space identity and memory state; route/data/jurisdiction policy; budget/cost uncertainty; provider request/batch IDs and native finish/usage; candidate quality report; evidence spans and contradiction states; dependency/reachability/hold and restored-deletion manifests. A model or provider response is untrusted feedback, not authorization.

| UCA | Contextual unsafe control action | Hazard / constraint | Scenario and verification |
| --- | --- | --- | --- |
| U13 | CA12/P: send private context to a remote provider because the content originated publicly or a local model failed | H7; C13 require classified permitted release packet, explicit fallback and sovereignty decision | Source page contains personal data; regex misses it. Enforce packet policy and fail closed; E37/E44 |
| U14 | CA11/P or T: load replacement generation/encoder before an old owned worker releases shared resources, or terminate an unrelated process | H9; C14 resource ownership and observed termination before reuse | Caller timeout leaves worker active; replacement OOMs interactive workload. E35/E36 |
| U15 | CA14/P or T: activate vectors/model/prompt with incompatible templates/dimensions, incomplete backfill or untested alias drift | H8; C15 immutable compatibility fingerprints, quality and atomic activation | Equal-sized vectors from different spaces get mixed. E21-E24/E41 |
| U16 | CA10/P or T: accept stale worker output after lease expiry/cancel, or enqueue downstream work without committed inputs | H8,H9; C16 fencing/outbox/idempotent acceptance | Two workers finish after retry; older model result overwrites accepted evidence. E25/E26 |
| U17 | CA13/N or P: fail to reserve or release pending budget as though an ambiguous remote timeout were unbilled | H9; C17 transactional reservations and unknown-outcome reconciliation | Response lost after provider accepted work; automatic retry doubles spend. E38/E42 |
| U18 | CA16/P or T: resubmit batch before reconciling original IDs, import duplicates/partial/mismatched results or treat cancel as zero cost | H8,H9; C18 durable remote/custom IDs and lifecycle states | Poll failure/restart loses submission state. E43 |
| U19 | CA15/P: promote a mention, quotation match, fixed confidence score or model agreement into a factual/operational/legal conclusion | H8; C19 typed source/derivation/review states with support/contradiction and abstention | Negated relation or legal proposal rendered as applicable obligation; E27/E31/E33 |
| U20 | CA15/N or T: omit retraction/invalidation after source/model/ontology evidence changed, leaving active products apparently current | H8; C20 dependency invalidation and superseded/quarantined status | Corrected advisory leaves stale graph edge and old briefing cache; E28/E30/E39 |
| U21 | CA17/P or T: purge held/referenced data or restore deleted context into serving/model queues | H1,H4,H8; C21 reachability/hold-aware deletion and restored tombstones | Backup restore brings personal notes into fresh cloud release packets; E39/E48 |
| U22 | CA11/N or T: omit deadline/cancel/drain enforcement while generator holds resources, starving reader/encoder work | H6,H9; C22 bounded queues, fair admission and cancellation that actually terminates owned work | Waiting thread stops but owned process keeps computing. E35/E36 |
| U23 | CA14/P: auto-promote newly discovered provider/model based on catalogue availability without license/capability/quality/sovereignty evidence | H7,H8,H9; C23 candidate discovery separate from promotion | Friendly alias changes tools or retention policy silently. E34/E41 |
| U24 | CA9/P: declare full-profile E2E complete from mocked inference/provider responses or source/schema assertions | H5,H8; C24 separate contract, real-local, hardware and live-provider evidence levels | Fake model returns perfect output while real tokenizer/tools differ. E16/E34/E37 |

All added commands are discrete; duration category is N/A for the command itself. Continued computation/leases are states: cancelled too late, cancellation omitted, renewal accepted unsafely or resources released too early are N/P/T UCAs. If a later design adds a sustained authority/enable signal, assess duration explicitly. Missing activation/release is not hazardous merely because it delays optional work; it becomes hazardous only when stale/unknown state is presented as current or safe.

C13-C24 allocate to R27-R58, ADR-0010 through ADR-0016 and E21-E51. Causal alternatives include legitimate no-new-source data versus failed acquisition; source contradiction versus parser/Unicode error; model OOM versus scheduler ownership error; provider refusal versus transport/access failure; incurred charge versus missing usage evidence. Diagnose from source/version/run/worker/provider receipts rather than assume the prototype or model is right.

Residuals: model truth and source completeness remain outside proof; prompt-injection resistance is limited to enforced effects; API aliases limit reproducibility; unknown provider policy denies dispatch. The model requires independent review when available and revision when real interfaces differ. No quantitative failure probability or completeness/certification claim is made.


Remote MCP extension: identity/resource-server controller CA18 authenticates caller, establishes/revokes session and authorizes scoped reads. U25 (P/T): accept a token/session issued for another resource/principal or retain revoked session authority, exposing a workspace (H1/H3/H7). C25 requires issuer/audience/expiry/scope/principal/workspace binding and revocation policy, tested E49/E50. U26 (N/P): omit per-request authorization or report SDK compatibility as actual assistant compatibility (H1/H5); C26 requires enforcement on every resource/tool read and an observed client/version evidence matrix (E49-E51). CA18 is discrete; duration N/A; stale retained session authority is a revocation/order defect. No outbound provider token is a substitute for caller authorization. These constraints allocate to R56-R58/ADR-0017.

## Implemented control refinement: local intelligence

This addendum maps implemented controls to the local intelligence boundary; it does
not close the full-system STPA scenarios or semantic-quality requirements.

| Unsafe control action | Implemented constraint | Executable evidence |
| --- | --- | --- |
| Release shared inference ownership on client timeout/crash while the daemon can still run | Fsync a private owner receipt before dispatch; retain on unknown outcome; reconcile owner/process/idle slot before release | `test_killed_generation_client_preserves_uncertain_reservation`, native wire reconciliation tests |
| Promote a schema-valid model statement solely because some quoted text exists | Preserve typed proposals, exact source spans and polarity; require an authenticated review through a separate SQL principal before cited products; actor labels remain attribution and human independence remains unproved | `test_proposals_review_cited_product_rejection_and_source_updates`, invalid-result and abstention tests |
| Accept late output after cancellation, lease loss or source replacement | Lock/recheck the fence and current source head in the transaction accepting proposals/completion | `test_abstention_and_cancelled_completion_are_distinct`, workflow fencing tests |
| Present withdrawn/stale source-derived statements as current | Active-document views and latest append-only review state constrain reads; product reads revalidate evidence and dependencies | Product withdrawal/source update tests and real MCP cited-product test |
| Disclose generator runtime paths, private actor/rationale or operational configuration through agent reads/errors | No generator/operator write tools in MCP; bounded error codes and product projections exclude those fields | Real MCP tool inventory/product assertions; source/package publication scans |

Residuals include semantic review error, model/runtime/shared-library supply-chain
trust, other clients bypassing local admission, cross-user/host resource contention,
incomplete graph resolution/diversity and full recovery/retention. A checked source
span is not semantic entailment, and an executable hash is not complete deployment
attestation. These limits remain in STATUS.md and ADR-0019.

## Private recovery control increment

The bounded checkpoint/restore path adds the following controls without closing
the target lifecycle analysis:

| Unsafe control action / loss scenario | Constraint and implemented control | Regression evidence |
| --- | --- | --- |
| Capture unrelated DB/object moments; declare a restore successful despite missing evidence | One read-only MVCC snapshot, all referenced immutable objects verified, document/span/product provenance checked; test actual fresh-target reads | `test_checkpoint_fresh_restore_citations_history_and_real_mcp`, `test_checkpoint_excludes_concurrent_acceptance` |
| Restore unfinished work and repeat an external effect or accept a historical fence | Disable collection; quarantine ready/running jobs, append recovery events, invalidate fences; interrupt incomplete runs/builds | Fresh restore test verifies failed jobs and rejects the historical fence |
| Import executable SQL or overwrite an existing installation through recovery | Fixed table names/bound JSON, matching packaged migration/profile versions, empty locked target and absent object root | Corruption/foreign-key rollback tests and populated-target rejection |
| Publish a backup as a sanitized consumer export | Explicit private classification, file mode 0600, ignored checkpoint extension, no publisher/MCP recovery tool; encrypted storage remains operator responsibility | Atomic/no-overwrite file test; publication scanner; review of recovery CLI/tool inventory |
| Treat capture timestamp as recovery of all subsequent accepted writes | State checkpoint boundary and excluded later writes; no PITR or zero-data-loss claim | Concurrent acceptance test demonstrates later data remains on source and is absent from restore |

At the ADR-0020 increment, retention/holds/tombstones and wider recovery were
open. The logical-lifecycle refinement below implements bounded policy controls;
old-host computation ownership, safe source re-enablement, external effect
reconciliation and host-level configuration recovery still need separate evidence.
See ADR-0020 and `docs/recovery.md`; a successful file hash alone is not recovery
evidence.

## Logical lifecycle control increment

This refines CA17 (retention/hold/retire/policy export) and CA8 (isolated restore).
The LC- namespace disambiguates lifecycle constraints from the earlier remote-MCP
U25/U26 and C25/C26 identifiers; neither scope supersedes the other.
The controlled state is the current logical-key policy, private retained records,
reader/worker authority and an independently retained dataset/revision receipt.
Feedback includes operation identity/revision, active holds, cancelled job fences,
exported policy hash and explicit busy/failure states. L1/L4/L5 and H1/H4/H5/H8
remain applicable. These are discrete commands; duration-type UCAs are N/A.

| UCA | Hazardous context / category | Derived constraint and allocation | Evidence |
| --- | --- | --- | --- |
| LC-U25 | CA17/P: retire a logical item while one of several preservation holds is active | LC-C25: serialize policy changes, reject held retirement and preserve hold history; no physical purge path in this increment | Hold/release/idempotency and restored-hold tests |
| LC-U26 | CA17/P: interpret a hold as permission to keep serving expired content | LC-C26: preservation and serving are independent; expiry hides all versions despite holds | Expiry-with-holds and clock-expiry/no-model-dispatch tests |
| LC-U27 | CA8/P or T: restore an older checkpoint without the current matching dataset policy or with incomplete hold/tombstone history | LC-C27: require independent hash/minimum revision, matching lineage, history/state consistency and monotonic tombstones before metadata commit | Older-checkpoint/newer-policy recovery, stale/wrong/corrupt/missing-tombstone refusal |
| LC-U28 | CA10/CA14/T: accept output or activate a stale view after retirement commits because a transaction snapshot predates a waited lock | LC-C28: acquire cooperative shared admission before any data transaction snapshot; exclusive lifecycle mutation cancels fences; filter derivative reads | Late repeatable-read, admitted-transaction, stale-fence and native vector/rerank tests |
| LC-U29 | CA6/P: return a retired historical body, quote, product or vector through a raw SQL grant or forgotten reader path | LC-C29: security-barrier content views, revoke raw reader grants, reject unsafe reader identities, withhold products containing suppressed selections | Direct SQL grants/predicate tests, historical-version tests and real MCP reads |
| LC-U30 | CA17/N: omit independent policy custody after a decision while an older backup remains the recovery source | LC-C30: operator retains current file and trusted minimum-revision receipt outside the rollback set; export failure is not decision rollback | Explicit export/restore contracts and stale-minimum test; simultaneous rollback of all trusted inputs remains an operational residual |

LC1: a collector sees an item again after retirement. It must record suppression
and continue other entries without accepting a new version of that logical item.
LC2: a late producer waits behind retirement. Admission before snapshot creation
prevents stale acceptance; already dispatched physical computation is not recalled.
LC3: a backup predates a hold/deletion decision. A newer independently retained
policy is applied before the restored database can serve those rows. A jointly
stale policy/hash/minimum cannot be detected offline and remains an explicit
assumption requiring operational custody evidence.

No full retained-record erasure, old-binary coordination, privileged
direct-writer containment, remote disclosure recall or complete E39/E45/E48 closure
is established. See ADR-0021 and `docs/lifecycle.md`; future context, cache and cloud
profiles must inherit these constraints rather than claim protection automatically.

## Bounded orphan-deletion refinement

CA19 is the operator's reviewed orphan-plan application (CA18 remains remote MCP authorization). Feedback is the private
plan digest, retained-reference set, policy revision and durable intent/completion
receipts. The control boundary excludes independent SQL/filesystem writers.

| Unsafe control action | Constraint | Discriminating evidence |
| --- | --- | --- |
| U31: delete an object because its document is hidden, while a retained version, hold or shared raw-feed record still references it | C31: use all snapshot and collection-run references; refuse unknown schema and reference-table row security | Held/retired historical and shared-feed reachability tests |
| U32: apply an old plan after reference, policy, root or file identity changes | C32: exclusively admit maintenance before snapshot; revalidate dataset, revision, reference set and every candidate before any unlink | Stale hold/reference, store substitution and changed-object refusals |
| U33: retry an ambiguous unlink with no durable intent or report completion before directory persistence | C33: durably bind intent to reviewed plan before unlink; require that intent for missing-file resume; fsync shards before completion | Intent failure, post-unlink fsync failure and killed-process restart tests |

Safe nonexecution includes rejecting unexpected inventory and unsupported row
security while preserving all files. An apply failure may leave some orphans
unlinked; receipts and the original plan must be retained. These controls do not
establish physical media sanitization, deletion of retained records or backup
erasure. See ADR-0022 and the revision-bound verification receipt.

## Durable acquisition refinement

CA20 is the operator's bounded due-only acquisition tick. Feedback includes due
state, unconfirmed attempts, raw hashes, successful HTTP status and per-source
partial/failure/deferred outcomes. Configuration, source content and response
headers remain untrusted; only an explicit external invocation starts a tick.

| Unsafe control action | Constraint | Discriminating evidence |
| --- | --- | --- |
| U34: acknowledge an unchanged response without intact accepted local evidence, mask a detected archive gap with a new body, or advance a validator after partial acceptance | C34: bind validators to URI/profile, require exact recovery of an observed prior gap, commit validators only with completed acceptance, omit validators after failed/unconfirmed work | Real 200/304 framing, missing/different-body refusal, partial-run replay and dirty unsolicited-304 tests |
| U35: send source-specific validators to another redirect resource or retain them after configuration/restore changes | C35: strip on redirects, reset on resource change and isolated restore, deny SQL/MCP access | Redirect, changed-resource, scoped-reader and recovery tests |
| U36: restart collection without retaining retry delay, dispatch unbounded work or hide independent sources after one failure | C36: reserve due state before dispatch, bound backoff/counter/tick size, retain per-source failure feedback | Killed collector, restart, bounded tick/backoff and independent-source tests |

The acquisition increment alone did not establish timer deployment or Retry-After
enforcement. Later supervisor/collector fixtures and ADR-0029 add bounded evidence;
global host quotas and complete operational acquisition acceptance remain open. A freshness success means representation
validation, not factual currency or independently verified content.

## Source reconciliation, diagnostics and supervisor refinement

CA4/CA20 additionally distinguish accepting a newly observed full representation
from replaying previously accepted immutable input. CA21 is the operator's
explicit local quality-diagnostic invocation; feedback includes a frozen suite
and protocol, model/config identity, per-query observations, numeric gate results
and distinct incomplete/completed outcomes. CA22 is the process supervisor's
start/stop/timeout control; feedback includes process identity, effective sandbox
settings, result state and observed child termination. These actions are discrete;
their duration category is N/A. Sustained resource consumption and surviving
children are controlled states, not a start command lasting too long.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U37 | CA4/CA20/P or T: preserve B as current when a serialized source observation returns to retained A, or treat 304(A) as complete reconciliation after partial B | H2,H8; C37: collector-only observed-current head authority, generic non-rewinding replay, no conditional request after failed/unconfirmed work; ADR-0024 | Native A/B/A, partial B/full A, dirty-304 refusal, generic replay and outbox-count regressions |
| U38 | CA21/CA9/P: treat a completed ranking run, synthetic labels, hash identity or a green workflow as semantic acceptance | H5,H8; C38: freeze suite/targets, bind predictions to exact suite/config, report per-split numeric gates and missing populations, separate execution completion from acceptance; ADR-0015 | Metric-oracle, wrong-suite, duplicate/unknown ranking, missing-population, explicit-abstention and negative-gate tests; public diagnostic remains synthetic |
| U39 | CA21/P: download or activate a model implicitly, or disclose private evaluation inputs through a public diagnostic workflow | H1,H3,H7; C39: preparation requires explicit invocation, pinned artifact bytes/hashes and licence acknowledgement; public workflow dispatch binds the approved synthetic suite digest; no activation or cloud request | Preparation hash/size/destination tests, reviewed workflow trigger and hard-coded suite digest; this is not complete model or supply-chain attestation |
| U40 | CA22/N or T: leave an overlong tick or its child running while reporting bounded service termination | H6,H9; C40: bound the service lifetime, terminate its complete control group, escalate after a grace interval, and verify result plus child identity; deployment reference | Native unit-parser checks and disposable supervisor probes; actual candidate/host execution receipt is required, not inferred from unit syntax |
| U41 | CA21/CA9/P: overwrite a prior diagnostic, expose private text/paths in logs, or conceal partial failure behind a new result | H1,H5; C41: fresh private output directory, durable no-overwrite suite/protocol and completed observations, bounded safe errors, distinct failed/completed receipts; diagnostic CLI | Private-permission, no-overwrite, corrupt-model, cooperative-budget and later-native-query-failure tests |

SC1/SC5/SC6/SC8 apply to these controls. L1/L2/L3/L4/L5 and H1/H2/H5/H6/H8/H9
remain the relevant losses and hazards; no new quantitative risk or completeness
claim is introduced. A completed diagnostic with unmet numeric targets exits
distinctly from execution failure. A workflow may preserve those negative results
while succeeding as an execution job; it cannot authorize model activation.

Quality evidence remains bounded: exact normalized query/group checks cannot
establish independently labelled holdout provenance or detect all paraphrases;
public synthetic cases cannot establish pretrained utility. The local diagnostic
budget is cooperative and can be exceeded by one already admitted native call's
existing timeout. Suite/protocol preparation is outside that timer; native artifact loading during
encoder calls is inside it and can consume or exceed the remaining budget.
Retained partial observations do not make an incomplete run complete.

Supervisor probes on a disposable runner, when executed, cover only their observed
properties. They do not establish operational host acceptance, timer activation,
database/HTTP acquisition, global resource fairness, OS egress policy or full-host
recovery. Reference deployment changes no original service. Feed-absence deletion,
whole-feed atomic replacement, privileged writer containment and full semantic
acceptance remain outside these implemented boundaries.

## Collector database-authority refinement

CA3/CA4/CA20 now include selecting and validating the CLI/reference collector's
database principal before a nonempty acquisition tick. The controlled state is
effective SQL authority, its credential source, the fixed acceptance outbox kind
and connection admission. Feedback includes privilege/schema refusal, explicit
unconfigured status, connection failure and normal durable source/run receipts.
SC3/SC5/SC6 and H1/H3/H4/H5/H6/H9 apply. These are discrete selections/checks;
duration-type UCAs are N/A.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U42 | CA3/CA20/P: collect using a general worker, administrative, owner or unexpectedly privileged principal | C42: dedicated collector group and effective column-grant/role/ownership validation before HTTP; missing or excessive authority fails closed; ADR-0027 | Native scoped-login acquisition plus deliberate extra-grant, broad-role and dangerous-identity rejection before dispatch |
| U43 | CA20/N or T: omit principal validation, silently fall back to a broad writer credential, or present empty-config success as acquisition readiness | C43: nonempty CLI configuration requires explicit collector DSN and validation; empty configuration performs no database/HTTP work and claims only non-execution | Missing-DSN and privilege-failure CLI tests, zero-dispatch checks, retained empty-config contract |
| U44 | CA4/P: acquisition can choose an arbitrary workflow kind or overwrite job authority instead of emitting the fixed document-acceptance event | C44: INSERT default fixes `document.accepted`; collector cannot insert `kind` or update job state; no elevated stored function | Direct SQL arbitrary-kind/job-update denials and scoped native ingestion/outbox tests; generic writer workflow remains separately tested |
| U45 | CA20/N or T: connection admission remains unresolved while an operator interprets HTTP deadlines as a bound on the entire tick | C45: finite driver connection timeout, explicit failures and external whole-process supervision; disclose DNS/multi-host and startup-validation limits | Native connection configuration/error checks and observed supervisor timeout; one timeout setting does not establish global tick latency |

C42–C45 reduce SQL authority at the CLI/reference-process boundary. They do not
establish per-source tenancy, filesystem evidence confidentiality, continuous
grant attestation or containment of a privileged direct writer. The trusted
Python API may still receive a broader writer explicitly. A collector retains
acquisition-state mutation and fixed-event payload authority; downstream workers
must preserve evidence validation, fencing and lifecycle checks.

Consider the alternative cause of a denied query: incompatible migration or a
missing required grant, rather than a reason to attach an administrator account.
Stop and reconcile credential/schema changes, then repeat synthetic native
acceptance. Published migrations are immutable. No original service or source
configuration changes are implied by this repository increment. The candidate
verification receipt, not this control allocation, establishes executed evidence.

## Isolated enabled-source service refinement

CA23 is the guarded acceptance harness's creation, validation and removal of its
owned fixture network namespace, HTTP process and service overrides. Its feedback
includes namespace identity, interface/address/route inventory, authentication
negative controls, observed HTTP requests, raw CAS identities, heads/outbox/run
state, service UID and cleanup outcomes. CA20/CA22 continue to govern acquisition
and timer/process lifecycle. SC1/SC3/SC4/SC5/SC6 and H1/H3/H4/H5/H6 apply. Creation
and deletion are discrete actions; duration is N/A for those commands. Surviving
processes and persistent network authority are states requiring observed cleanup.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U46 | CA23/P or T: bind a public-classified fixture address or launch acquisition in the host namespace, or with an external interface/route | C46: fixed owned namespace, distinct namespace identity, loopback-only interfaces and explicit address/route checks before binding/dispatch; no veth or external route; ADR-0028 | Native isolation inventory and fail-closed preflight controls; unsupported namespace capability cannot be counted as a passing run |
| U47 | CA20/CA23/P: make enabled acquisition pass by disabling production DNS/address policy or injecting a fixture-only application override | C47: unchanged HTTP resolver/address/transport code; read-only fixed hosts mapping and service namespace supply the fixture; no runtime bypass flag or monkeypatch | Actual installed service requests to the isolated synthetic endpoint and retained fixture identities; no Internet DNS or TLS claim |
| U48 | CA23/CA9/P: report scoped password-authenticated database integration although local trust or a wrong endpoint bypasses credentials | C48: explicit SCRAM local/host configuration, valid scoped login and wrong-password rejection at the same Unix endpoint before acceptance | Positive connection plus authentication-specific negative control; connection unavailability alone is not authentication evidence |
| U49 | CA20/CA22/CA9/P or T: report enabled scheduling/recovery from a process exit while requests, current heads, evidence, outbox or due state disagree | C49: observe 200, real accelerated-timer 304, 503/backoff, non-due no-dispatch and unconditional changed-body recovery; cross-check requests, CAS, PostgreSQL and journal UID | Candidate-specific manual enabled-source receipt; synthetic acceleration is not validation of production intervals or load |
| U50 | CA23/N or T: remove a namespace or report cleanup while owned service/HTTP children still hold resources, or delete a preexisting resource | C50: reject preexisting fixed targets, record ownership after each creation, stop/observe owned processes before removal and report cleanup failure explicitly | Failure-path/cleanup postconditions and controlled child/process identity; disposable runner removal is not a reusable host rollback procedure |

These controls prevent the acceptance fixture from introducing a new operational
network exception. They do not prove every kernel, runtime or privileged actor
preserves isolation; the harness itself is trusted administrative code. A public
address string being classified as global is neither Internet ownership nor a
reason to route real traffic to it. The isolated namespace must remain without an
external path for the complete enabled-source run.

The run is explicitly synthetic and manual. No original data, source endpoint or
host configuration is required. Linux namespace/systemd/capability availability,
password authentication, actual timer activation and cleanup require observed
candidate execution; syntax, disabled-source probes or fixture setup alone do
not establish them. No TLS, source truth, production reliability, independent
semantic acceptance, reader tenancy or full E2E programme closure is implied.

## Bounded server-advised retry refinement

CA3/CA5/CA20 include admission of a later source attempt after an untrusted final
429/503 response. Feedback is a bounded error disposition, persistent source
failure count and next-attempt timestamp; no raw response header is authority.
SC2/SC5/SC6 and H1/H2/H5/H6/H9 apply. Retry scheduling is a discrete database
decision; a worker sleeping while retaining resources is not its implementation.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U51 | CA3/CA5/P or T: retry automatically before accepted bounded server advice/local backoff, or lose the delay at process restart | C51: persist the maximum of reservation, ordinary failure-backoff deadline and bounded server deadline using database time; no worker sleep; ADR-0029 | Native delta/date, backoff-floor, restart and no-early-dispatch cases |
| U52 | CA5/P: accept ambiguous, malformed or arbitrarily large metadata as indefinite scheduling authority, or describe a capped wait as fully honouring a larger minimum | C52: bounded single-field parser, seven-day cap with `SOURCE_RETRY_AFTER_CAPPED`, explicit invalid-input fallback and disclosed longer-minimum trade-off | Duplicate/date-comma, oversized/invalid input, cap-boundary and raw-header-canary tests |
| U53 | CA5/P or T: schedule from an origin-supplied clock or misinterpret an obsolete date while claiming exact deadline compliance | C53: UTC date handling with database-clock admission, explicit RFC 850 year-window and clock-skew limits; origin Date/Age does not replace local scheduling authority | Three-format/date-boundary, past-date and database-time cases; tests do not attest clock correctness |
| U54 | CA20/CA9/P: apply an unreviewed manual retry, resource reset or restored-source enable while reporting continuous automatic server-delay protection | C54: explicit manual refresh overrides due time; new failure re-establishes bounded advice; configuration reset and disabled-source restore/re-enablement remain disclosed overrides | Manual override, new-failure persistence, changed-resource and restore contracts |
| U55 | CA5/CA9/P: return raw retry headers/URLs, accept an error body as evidence, or present a per-source timestamp as shared-host rate governance | C55: bounded safe errors only, no error-body acceptance, final 429/503 scope and no shared-host/redirect-delay claim | Wire-to-collector rejection/canary cases, independent-source progress and installed-wheel regression scope |
| U56 | CA5/CA7/P or T: report server advice as durably scheduled after the failure transaction loses its connection or commit acknowledgement | C56: return `COLLECTION_STATE_PERSIST_FAILED` when persistence is unconfirmed; retain the last confirmed pre-dispatch reservation and reconcile observed database state on restart | Native backend termination while a fixture returns advice, explicit persistence-failure result, restarted reservation/interrupted-run checks |

A malicious or faulty origin can still affect its source's availability within
the chosen horizon. The cap can retry earlier than a legitimate longer minimum;
manual operator actions can override the timestamp. Those are explicit policy
limits, not proof of complete Retry-After compliance. Simultaneous sources at one
host, clock jumps, external server behaviour, redirect-delay semantics and actual
provider quotas require separate controls/evidence. A crash between advice receipt
and commit cannot retain uncommitted advice; a lost commit acknowledgement can
leave an unknown outcome. The database, not the original HTTP error disposition,
determines what survived. Failed manual dispatch preserves an older later
reservation; successful manual acceptance can reset it to normal polling. No original endpoint, new
MCP authority or operational deployment change is implied by this increment.

## Native transport trust-verification refinement

CA3/CA4 depend on connection-time destination checks, authenticated TLS identity
and bounded native I/O. CA9 must decide whether transport evidence actually
exercised those effects or substituted a permissive/mock boundary. Feedback
includes native peer handshake/request observations, original hostname/SNI/Host,
classified resolver results, actual connection destination, elapsed waits and
fixture cleanup. SC3/SC5/SC6 and H1/H3/H5/H6 apply. TLS setup, connection and
verification decisions are discrete; ongoing waits require the existing absolute
deadline and observed owned-task termination.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U57 | CA3/P: connect to a prohibited address from a mixed DNS result or resolve the hostname again after validating a different answer | C57: validate the complete answer set and pass the admitted address to the actual TCP connection; classify mapped-private addresses before admission; ADR-0030 | Mixed/mapped/blocked/empty resolver cases, observed connection destination and no-connect rejection controls |
| U58 | CA3/CA4/P: accept a TLS peer using only a valid chain or pinned IP while losing the original hostname, or bypass verification to exercise a fixture | C58: preserve original-origin SNI/Host and certificate hostname/chain checks; fixture CA trust exists only inside tests, never machine trust or a production bypass | Native trusted peer, wrong-host and untrusted-chain cases with no accepted negative HTTP request |
| U59 | CA3/CA5/N or T: reset the complete deadline at TLS/redirect boundaries or retain owned resolution/I/O after the caller stops waiting | C59: propagate one absolute monotonic deadline through phases, bound native handshake/read and DNS subprocess cleanup | Actual handshake/body-stall elapsed tests, redirect-budget cases and resolution/owned-task termination evidence |
| U60 | CA9/P: call mocked TLS, route injection, connection refusal or the existing plain-HTTP service receipt operational TLS assurance | C60: identify each fixture injection, require positive plus independent trust-negative native peers and keep unit/native/service evidence levels separate | Revision-bound installed-wheel inventory, peer-side observations and explicit Internet DNS/PKI/operational limits |
| U61 | CA7/CA9/P: expose certificate paths, private keys, resolver strings or peer content through transport diagnostics | C61: bounded safe errors and ephemeral private test keys, no system trust mutation or raw failure logging | Error-canary/redaction assertions, local fixture custody and publication checks |
| U62 | CA3/P: treat an explicit zero port as an omitted default while describing destination-port validation as complete | C62: distinguish missing port from zero and reject explicit zero under the unchanged 80/443 policy | URL-policy regression before socket dispatch; this does not assert a prior private-network exploit |
| U63 | CA7/N or P: a native trust/transport failure triggers a nonexistent exception-class lookup, masking the intended bounded failure disposition | C63: map actual installed transport exception families and exercise negative native peers instead of inferring error handling from success | Wrong-host, untrusted-chain, expired-certificate and stalled/invalid TLS cases with safe errors |
| U64 | CA3/CA5/P or T: treat a readable resolver pipe prefix as a complete message, then block past the absolute deadline or allocate from an unbounded declaration | C64: bounded JSON bytes over private IPC, bounded `recv_bytes` in one owned receiver thread and remaining-budget queue wait; reject excessive complete answer sets without truncation | Replayed partial-frame stall, excessive packet/answer/address, EOF and malformed-JSON cases with actual subprocess/IPC execution |
| U65 | CA5/CA7/N or P: return a deadline result while an owned resolver child/thread remains active and silently claim cancellation completed | C65: terminate/join child with bounded kill fallback, join receiver and close endpoints; explicit cleanup failure if termination is unobserved; disclose startup/cleanup overhead | Entered-child and partial-frame deadline cases with observed child/thread termination; daemon status alone is not cleanup evidence |

The harness, OS TLS/network implementation and pinned dependencies remain trusted
parts of these experiments. Public-address classification is not complete egress
confinement, and synthetic CA trust is not operational PKI acceptance. A passing
native fixture cannot establish Internet DNS, revocation policy, universal trust,
hostile-kernel containment or full transport conformance. No original endpoint,
private certificate inventory, model download or operational service change is
required by this verification increment.

The original partial-frame case is controlled fault injection, not an observed
operational attack. Its correction bounds result reception and validates the
returned packet; libc/NSS work before that packet exists is still trusted and
its internal memory allocation is not bounded by the Python answer cap. Process
creation and cleanup have separate costs. API portability does not establish
Windows/macOS or every Linux configuration without native execution evidence.

## Offline advisory-observation refinement

This allocates the existing U19/C19 and R36/R37 to the bounded offline envelope
in [ADR-0031](../adr/0031-offline-advisory-observations.md); it introduces no new
controller or capability-closure claim. The hazardous action remains promoting
an attributed source claim into an unsupported operational conclusion (H2/H8).

| Existing constraint concern | Bounded contract allocation | Required evidence and limits |
| --- | --- | --- |
| Source scores or reported exploitation appear independently verified | Each observation retains its publisher and evidence references; conflicting CVSS/EPSS/exploitation claims remain individually attributed | Round-trip conflicting observations; references do not establish existence, integrity, entailment, publisher independence or confirmed exploitation |
| Distinct events collapse into one apparently current date or priority | Preserve publication, modification, observation, score and reported-exploitation dates; no target inventory or inferred remediation policy | Date/primitive-bound cases; CVE presence and CVSS/EPSS values cannot establish applicability, exposure or a patch deadline |
| Untrusted normalized JSON gains authority or discloses private input through diagnostics | Bounded strict parsing, immutable nested models, duplicate/unknown-key and malformed/nonfinite/structural rejection; fixed public parser errors | Adversarial canary and deterministic canonical round-trip tests; raw model-validation diagnostics remain unsafe to publish |

Authored fixtures establish only the normalized contract. Upstream acquisition,
schema mapping, affected-version matching, evidence resolution, persistence,
retractions and operational assessment require separate implementation and
verification. This contributes bounded evidence toward E31; it does not close
E31/E32 or the vulnerability-intelligence profile, nor establish source truth or
CVSS vector/score consistency.

## Transactional retired-record purge refinement

[ADR-0032](../adr/0032-transactional-retired-record-purge.md) refines CA17
(review/apply purge) and CA8 (restore), with the operator, purge process, job
coordinator and retrieval builder as interacting controllers. The controlled
state comprises retained SQL records, their supported derivative references and
permanent lifecycle history. H1/H4/H8 and U21/C21 apply. Feedback must distinguish
a reviewed impact plan, an unconfirmed commit, a durable purge event, a private
receipt copy and actual postconditions. The discrete purge command has no
duration category; delayed execution and premature completion are timing/order
concerns. This refinement defines acceptance obligations, not executed evidence.

| UCA | Hazardous context / category | Derived constraint and allocation | Required discriminating evidence |
| --- | --- | --- | --- |
| U66 | CA17/P: delete only one version, delete an expiry-only item, or delete held/shared collateral while interpreting a document ID as the complete disposal unit | C66: require the permanent source/key tombstone, recheck all holds, traverse all versions and supported derivatives, retain shared snapshots and block held collateral; bind the exact impact set to the reviewed plan | Multiple versions, shared snapshots/feed bodies, shared immutable products and held-neighbour refusal |
| U67 | CA17/P or T: apply a stale plan or accept producer output after deletion, including a builder changing an invalidated generation back to ready | C67: exclusive lifecycle admission before snapshot, exact state revalidation, job-fence rejection and conditional generation acceptance; preserve neighbouring vectors while invalidating affected corpus claims | Stale plan and real worker/build/activation interleavings; no target reconstruction or incomplete ready generation |
| U68 | CA17/CA7/P or T: publish success before commit, repeat deletion after a lost response without checking durable identity, or treat a receipt-write failure as database rollback | C68: purge event/revision/deletions commit atomically; replay checks exact operation/request/plan binding; uncertain COMMIT remains an error until durable reconciliation | Mid-transaction rollback, exact/conflicting retry, lost-response reconciliation and an explicitly injected post-commit acknowledgement failure |
| U69 | CA8/P or T: restore a pre-purge checkpoint under newer policy while merely hiding the resurrected records | C69: validate purge history and current independently retained policy; reject historical target records before object acceptance; accept compatible post-purge state only | Pre-purge refusal with absent object root, post-purge round trip, stale/missing/incorrect policy and explicit known-history adoption cases |
| U70 | CA17/P: execute deletion using broad owner/writer authority or omit optional stored retrieval dependencies because a runtime feature is disabled | C70: separate explicit purger authority, supported current core/profile history and full dependency visibility; reject unsupported schema/RLS or broadened identities; MCP remains read-only | Scoped positive principal, owner/superuser/writer/collector negatives, core-only and retrieval cases |
| U71 | CA9/P: report transactional record deletion as erasure of shared feeds, WAL, backups, media or already disclosed data, or infer reversibility from an older checkpoint | C71: disclose retained copies/policy identifiers and destructive SQL-state boundary; separate orphan GC, backup expiry and media controls; old backups are not authorized unpurge | Receipt/documentation scope review, preserved shared references and historical restore rejection; no global-erasure or legal-compliance claim |

Causal cases include a valid-looking plan that predates a new shared derivative
(U66/U67); a builder retaining the old corpus in memory after its target vectors
were removed (U67); a completion file published while the database context has
not yet committed (U68); and a recovery operator assuming a newer tombstone also
removes old bodies from a checkpoint (U69). The controller must observe the
enforced dependency/commit/recovery state rather than infer it from an earlier
command acknowledgement. Keeping the durable decision in the same transaction
removes the external-journal/SQL atomicity gap; it does not prove file custody or
the freshness of jointly rolled-back trusted policy inputs.

Old binaries, privileged direct writers and independent filesystem writers do
not participate in the advisory-lock contract and require operational exclusion.
Already disclosed text and historical backups are outside this actuation path.
Refusing an unsupported or held closure leaves records retained and suppressed;
operators must see that incomplete disposition instead of assuming deletion.
These controls contribute to E39/E48 without closing full retained-data erasure,
backup expiry, remote-copy disposal or whole-host recovery.

## Store admission after database-backend loss

[ADR-0033](../adr/0033-durable-store-admission.md) refines CA19 orphan deletion
and CA4/CA8 evidence acceptance/restore against H4 and SC4. The GC controller's
process model can incorrectly retain "exclusive admission owned" after the SQL
backend disappears. The controlled filesystem is still active, and a cooperative
database writer can be admitted before GC observes that feedback loss. A prior
SQL snapshot or heartbeat does not atomically authorize a later unlink.

| UCA | Hazardous context / category | Derived constraint and allocation | Required discriminating evidence |
| --- | --- | --- | --- |
| U72 | CA19/P or T: unlink a formerly unreferenced object after backend loss admits a writer that reuses it | C72: retain independent exclusive store-root inode admission across final reference validation, unlink and directory fsync; producers retain shared admission through acceptance commit | Actual backend termination after validation, cross-process reuse attempt and evidence/reference postconditions |
| U73 | CA4/CA8/P or T: release filesystem admission after put but before metadata commit, or accept a cached raw pointer without new put | C73: shared admission covers the complete ingest/collection/restore transaction lifetime, including 304 reuse and collector intermediate/final commits; standalone put is not a future acceptance token | Commit-boundary, cached-304, multi-commit and restore interleavings with real processes/SQL |
| U74 | CA19/P or T: validate SQL references before waiting for filesystem exclusion, then use that stale snapshot after ownership loss | C74: database admission then filesystem admission then final state; reject failed validation before deletion; never reverse the lock order | Backend loss during admission wait and writer-before-validation cases; bounded refusal without unlink |
| U75 | CA19/CA4/P: lock one inode but mutate a substituted root, or let nested/thread contexts release another operation's ownership | C75: anchored no-follow directory identity, explicit active ownership and deterministic descriptor lifetime; unsupported locking fails closed | Symlink/root-identity, independent instance/process, nesting, timeout and cleanup cases |
| U76 | CA9/P: report advisory local filesystem admission as protection from old binaries, another database's references or arbitrary privileged writers | C76: one authoritative dataset/store pairing, local-Linux evidence scope, old-process quiescence and explicit nonparticipant exclusion; suspend GC when protocol compatibility is uncertain | Deployment/rollback review and stated filesystem/UID/process assumptions; no universal or cross-host guarantee |

Causal sequence S-GC1: GC validates a candidate, its SQL backend terminates, a
writer is admitted and commits reuse, then GC deletes the object using its old
reference set (U72). S-GC2: a put-level lock is released before the surrounding
connection context commits, leaving the same interval despite apparently locked
publication (U73). S-GC3: GC waits for filesystem ownership after validating SQL;
its backend dies and an intervening writer commits before GC acquires the lock
(U74). Prevent these sequences by ordering and retaining both admissions, rather
than treating a live caller or recent heartbeat as ownership evidence.

Purge/deletion commands are discrete; the concerns above are provision and
ordering, not a command "held too long." Delayed lock acquisition is instead an
observable bounded maintenance/acceptance failure. Suspending GC safely retains
orphan bytes while this integrity boundary is unverified. Actual native execution
and revision-bound receipts are required before describing the counterexample as
closed; storage media erasure, distributed-lock correctness and whole-host
recovery remain outside this refinement.

## In-flight query coalescing

[ADR-0034](../adr/0034-bounded-query-coalescing.md) refines local model execution
and retrieval response control. A caller waiting for another computation must not
be mistaken for its owner, and a prior result must not become an unvalidated
completed cache. This contributes to E10/E23/E34/E39 without closing them.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U77 | Return a vector from a different query/model contract or share mutable result ownership | C77: exact packet digest, instance scope, manifest snapshot and independent result copies | Different keys/instances, native oracle and caller mutation |
| U78 | Release inference authority when a follower times out, or leave followers blocked after owner failure | C78: follower wait has its own bound; only owner controls computation; every owner exit wakes followers and removes flight | Timeout during blocked owner, typed/unexpected failure, retry and native admission tests |
| U79 | Admit unbounded duplicate waiters or reuse an inherited locked instance after fork | C79: bounded distinct owners and aggregate waiters, fail-fast refusal and PID guard before mutex | Capacity refusal and actual fork while parent mutex is held |
| U80 | Treat a completed query result as indefinitely valid after artifact or policy changes | C80: remove completed flights, reverify later native calls, and preserve per-search database/lifecycle checks | Native model tamper after completed identical query; existing lifecycle/retrieval suite |

## Inference custody and build evidence refinement

[ADR-0037](../adr/0037-inference-custody-python-sbom.md) refines local inference
authority and publication evidence. These constraints retain the trusted-account
and public-build-input assumptions; they do not establish an adversarial same-UID
sandbox, legal clearance or complete native composition.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U81 | Release admission or remove a substituted reservation after locking another inode or parent | C81: anchored no-follow directory operations, safe custody, stable lock/parent identity and observed receipt bytes/identity before removal | Real symlink/FIFO/hardlink, replacement, parent/lock rename, crash and native terminal-response cases |
| U82 | Reconcile an unreadable prior process as terminated and dispatch overlapping inference | C82: unavailable start identity remains unknown unless the kernel proves no such process; preserve verified PID-reuse and current idle-peer rules | Live/denied/error probes retain marker; actual exited process and verified reuse permit bounded recovery |
| U83 | Publish signed evidence as proof of complete dependencies or legal redistribution despite omitted native bundles or missing notices | C83: exact installed inventory, strict schema/regeneration checks, explicit incomplete composition and version/text-specific unresolved dispositions | Schema/graph tamper controls, changed evidence/version refusal and documented native/upstream-only gaps |
| U84 | Sign supplementary reports unrelated to the tested public source/runtime or allow PR code signing authority | C84: final v2 digest binding, exact six-file set, all native/policy gates and isolated main-only signer | Source/hash mutation refusal, PR/main permission and provenance identity verification |

An unavailable process-start token can follow either exit or access failure;
equating those observations creates U82. A valid JSON SBOM can omit valid graph
edges, and a valid signature can bind incomplete or misleading content; schema
validation alone therefore cannot close U83/U84. Regeneration, reviewed policy,
explicit limits and independently verified signing identity provide distinct
feedback. Exact successful results remain revision-bound.

## Recorded native files and supplementary notices

[ADR-0038](../adr/0038-native-file-evidence-notices.md) refines C83/C84 without
equating file identity, component lineage and redistribution clearance.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U85 | Accept changed native bytes because package metadata/text hashes still match, or combine files from distinct reviewed wheel variants | C85: compare the complete recorded ELF set and bytes to one reviewed supported variant; retain the RECORD-derived and static/loader limits | Changed/missing/added ELF, mixed variants, unsupported ABI and malformed data refusal; actual installed profile comparison |
| U86 | Publish inferred native versions or supplementary upstream text as a complete resolved graph, complete notices or legal approval | C86: separate observed ELF identity and declared dynamic names from unresolved lineage; bind exact upstream identities/texts and keep missing NOTICE/source/composition work visible | No execution/import of inspected code, public-field checks, changed source/text/version refusal and explicit incomplete outcomes |

V3 allocates C84 to four supplementary files and an exact eight-file set per
profile. Test the actual isolated signer admission script, including requested
Python optimization, byte substitution, special files and incorrect run/source
identities. These checks supplement producer semantics; they do not replace
independent component identification, complete release review or operational
runtime observation.

## MCP major-version and dependency adoption

[ADR-0039](../adr/0039-mcp-v2-dependency-refresh.md) refines the existing public
workbench boundary. The maintainer controls dependency adoption through CA1 and
CA9 feedback; the adapter controls CA6/CA7 with its fixed read dispatch, selected
protocol version, validated arguments and explicit error state. Package
registries and the selected client remain external. An ambient tracing provider
is an additional potential disclosure recipient when the adapter is embedded.
This analysis allocates to R06, SC1/SC3/SC5 and existing C8/C12/C83–C85; it adds
no remote authorization or operational-deployment claim.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U87 | CA6/P or CA7/N: after an SDK upgrade, execute a request without application validation or expose a backend failure as successful or detailed output | H1/H3/H5; C87: retain explicit schema checks before fixed dispatch, bounded sanitized results and real modern/legacy stdio negotiation | Invalid extra fields/types/IDs and unknown tools cannot call the backend; both protocol modes retain seven reads and native reader restrictions |
| U88 | CA1/P or CA9/T: approve an SDK using the old process model while its new automatic tracing or changed dependency bytes escape the reviewed disclosure/evidence boundary | H1/H5; C88: explicitly remove SDK tracing, refuse incompatible opt-out contracts and verify the newly resolved installed inventory, licence/native identities and exact revision | Ambient-tracing request probe, preserved nontracing middleware, opt-out drift refusal, actual selected-wheel review and fresh installed/native matrix |

The U87 causal scenario starts with removed low-level handlers or permissive
SDK defaults being mistaken for the application's admission checks. Listing a
schema does not enforce it; the adapter must validate before invoking the read
service. An error path must remain an explicit sanitized failure, never an empty
successful corpus. Failure to negotiate prevents service use and must be visible
to the caller; restoring broader authority is not a recovery mechanism.

The U88 scenario starts when a maintainer assumes an API-only telemetry package
cannot disclose anything. A global provider installed by another embedding
component can activate previously inert instrumentation. Explicit middleware
removal prevents this adapter's SDK spans; it does not control independent
client or embedding-process instrumentation. A changed provisional opt-out must
fail construction until reviewed, with a coherent protected rollback available.
New package hashes require actual selected-wheel inspection rather than an
automatic policy rewrite. Fresh green CI for another commit is stale feedback.

For these discrete adoption and response actions, duration is N/A. Omitting an
optional update delays maintenance without itself creating a scoped loss;
omitting a required security correction while claiming acceptance remains
U1/U12. Returning a valid result after an SDK cancellation does not prove its
underlying worker thread stopped: inference admission and database authority
must remain owned by the actual operation until completion. Existing process,
fencing and resource-lifetime tests remain applicable. External assistant
compatibility, comprehensive cancellation/resource scheduling and native/legal
composition remain bounded by their separate acceptance evidence.

## Feed item identity, framing and cited-product binding

| UCA | Unsafe control action | Constraint | Discriminating evidence |
| --- | --- | --- | --- |
| U89 | CA4/P: accept every unchanged item in a changed feed container as a new immutable version and outbox event | H8,H9; C89: collector compares each item with its current head by recomputed identity under scoped column grants; unchanged content keeps the head and enqueues nothing; ADR-0040 | Writer and validated collector feed-window regressions with exact document, snapshot, job and retained-container counts |
| U90 | CA5/P: resolve repeated `Content-Encoding` or `Location` fields by the last occurrence | H2,H3; C90: repeated framing fields fail closed with typed errors; redirect fragments are removed before validation, never sent | Raw-wire duplicate, non-ASCII, fragment and downgrade controls through the actual client |
| U91 | CA6/N: deny all search because ordinary collection grew the corpus past reference build bounds | H2,H6; C91: an over-limit corpus is reported as degraded drift while builds and activation keep enforcing bounds | Native growth-past-limit search, build and activation regression |
| U92 | CA15/P: serve a briefing whose digest is self-consistent but whose items misstate the accepted assertions they cite | H8; C92: every read compares each cited item with the live accepted assertion projection | Writer-authority forged statement, polarity and source cases |
| U93 | CA11/P: release single-slot inference admission when the admitting parent dies while its model child continues computing | H9; C93: children bind their own lifetime to the expected admitting parent and refuse unbound work; exits are classified before result decoding | Actual SIGKILL of an intermediate parent with a blocked child, unbound-child refusal and exit/shape classification cases |
| U94 | CA10/P: retry deterministic invalid model output as a backend fault | H9; C94: unstorable model text is invalid model output and terminal | NUL claim cases leave no assertions and do not rerun inference |
| U95 | CA14/P or CA7/N: let one content-refused document block every index generation, or hide its absence from semantic coverage | H2,H8; C95: content-determined encoder refusals become recorded member exclusions with fixed reasons; runtime failures and a majority-excluded corpus still fail; coverage is reported | Real-encoder zero-width and over-length exclusions, majority and runtime-failure refusals, purge and profile3 adoption cases |
| U96 | CA12/P: dispatch remote work with unknown sovereignty facts, an unallowed data class or task, a missing credential, or without a persisted decision | H7; C96: deny by default; record every decision before any connection; unknown facts deny even with an exception; exceptions are task-scoped and recorded as exceptions | Denial matrix with a backend that fails on any connection attempt; recorded denial rows |
| U97 | CA13/P or CA7/N: exceed a hard cap under concurrent workers, or count unreported or unknown usage as zero | H9; C97: per-route-and-currency transactional lock; exposure counts reservations for every attempt that may have reached the provider; currencies never combined | Twelve concurrent reservations across two currencies; missing/negative usage and dropped-response exposure; mutation check of the lock |
| U98 | CA10/P: replay a remote attempt whose outcome is unknown or failed, or let a local failure create remote work | H7,H9; C98: one logical operation per job, prior non-released attempt blocks dispatch, terminal job failure, distinct local and route job kinds | Dropped-response replay refusal with zero connection; second worker pass idle after each provider outcome |
| U99 | CA13/P: lower remote exposure without provider evidence, or let the spending identity settle its own attempts | H9; C99: settlement only by a separate accounting role that is not a writer; provider bases require an evidence digest; only a still-reserved attempt settles at zero; settled rows are final; ADR-0043 | Writer, reader, collector, lifecycle and dual-role refusals; column-grant refusals; basis, currency and conflict cases; mutation of the writer check |
| U100 | CA10/CA13/P: settle an attempt a live worker can still send or complete, so spending escapes the ledger | H7,H9; C100: database refuses settlement of reserved or dispatched rows younger than ten minutes of database time the writer cannot set; the request deadline starts before dispatch commits and expired work is refused before send admission; partial sends and host suspend remain transport limits; the attempt row lock orders settlement against late outcomes | Code and database in-flight refusals; writer `updated_at` refusal; stalled-worker release with zero connection; settlement-versus-late-outcome race under read committed and repeatable read; busy lock refusal |

The ledger integration review in [ADR-0044](../adr/0044-ledger-integration-boundaries.md)
refines C97/C98: reservation admission selects Read Committed before waiting
for the route/currency transaction lock. Two waiting sessions with Repeatable
Read defaults must admit only one attempt for the cap or unresolved operation.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U101 | CA17/N: retained cloud accounting makes every content purge unavailable | H2,H6; C101: every inventoried table has a fixed primary key; ledger attempts and settlements remain outside the deletion closure; ADR-0044 | Scoped purge plan/apply/replay with five real ledger states preserves exact accounting rows and exposure |
| U102 | CA2/P: publish a merge message containing an agent session link after a clean branch scan | H1; C102: preflight exact planned public text and use explicit reviewed merge messages; preserve historical findings and full metadata checks | Clean native Git branch followed by a synthetic session-linked merge is refused by both preflight and metadata scan; unsafe input and redaction controls |

The U89 scenario starts with a feed that changes one entry or a channel
timestamp at every poll. Hash identity correctly distinguishes containers, but
treating the container digest as item identity multiplies storage, index and
model-queue work while search hides the duplicates. Granting the collector
read access to titles and text would solve it with broader hostile-input
authority; recomputing identity in the head's container needs only digests.
U92 starts from trusting a product digest as evidence: a digest proves bytes,
not that those bytes still agree with reviewed records.

## Supervised profile boundary refinements

[ADR-0045](../adr/0045-bounded-operational-profile.md) adds these controls to the
first supervised profile. They refine existing requirements rather than closing
the full operational, model-quality or recovery scenarios.

| UCA | Hazardous context / category | Derived constraint and allocation | Discriminating evidence |
| --- | --- | --- | --- |
| U103 | CA6/N: valid pages routinely exceed the MCP serialized result limit, preventing evidence retrieval | H2,H6; C103: page intact records against actual UTF-8 byte budget, preserve explicit continuation scope, and refuse a single unrepresentable record without skipping it | Multibyte/control-character records, bounded-window continuation and complete record reconstruction |
| U104 | CA10/P: source text becomes trusted tokenizer control IDs | H3,H8; C104: separately tokenize literal source and trusted template, verify automatic-prefix capability, submit exact IDs and version generator identity | Native special-token positive/negative controls, exact submitted IDs and old-kind non-claim |
| U105 | CA6/P: an unforeseen readable relation/column or reachable role bypasses filtered reader projections | H1,H3; C105: exact effective reader relation/column allowlist and no alternate application identity | Direct, inherited, PUBLIC, column-only and SET ROLE grant refusals with normal core/retrieval controls |
| U106 | CA7/P: a successful empty/partial tick implies healthy collection or complete processing | H2,H6; C106: explicit health thresholds, denial of unconfigured/stale/error/unavailable states, supported-job-only bounded ticks and honest all-kind backlog counts | Failure states and cap/idle distinction, real non-root service execution and restart |
| U107 | CA4/P: adding workers silently exposes private evidence or grants shared writes | H1,H3; C107: opt-in pre-provisioned group-readable creation, anchored custody checks, no implicit permission repair, separate credentials and read-only consumer mounts | Private-default/unsafe-group/symlink/mode refusal, actual account read and write denial across new objects |

The relevant process-model errors are character counts treated as wire-byte
counts (U103), a concatenated prompt treated as uniformly trusted syntax (U104),
future grants assumed equivalent to reviewed projections (U105), process exit or
a bounded idle poll treated as complete service feedback (U106), and shared-group
membership assumed to imply safe object custody (U107). The concrete environments
include multibyte/control-character source text, tokenizer control spellings,
direct/inherited/PUBLIC grant drift, exhausted-claim reaping, restrictive umasks,
named ACLs and the collector's setgid syscall restriction. Constraints allocate
to the adapter, generator identity, reader admission, health/worker feedback and
anchored storage creation respectively. Operator-controlled ancestors, group-wide
CAS disclosure and separately provisioned egress/alerting remain assumptions.
These are discrete return/report/accept/dispatch actions; duration categories do
not apply to the actions themselves. Halt/refusal preserves prior accepted data
and reports failure; it does not establish useful model quality or recoverability.


## Authenticated API first-slice allocation

[ADR-0046](../adr/0046-authenticated-api-acquisition.md) refines existing controls
for the bounded JSON-page profile. It does not establish licensed-provider
operation, complete rights enforcement or full STPA closure.

| Existing UCA | First-slice constraint allocation | Discriminating evidence and limits |
| --- | --- | --- |
| U1 / C1 | Public code/configuration contains no operational endpoint, credential value, provider response or private source catalogue; authentication references remain operator-controlled | Synthetic fixtures and exact source/artifact/message review; scans do not prove arbitrary content anonymous |
| U4 / C4 | HTTPS-only configured endpoint, public pinned destination/TLS identity, no redirect or response-selected destination; only a bounded encoded continuation parameter | Native denied-origin/redirect/auth-header cases; no generic SDK behaviour or alternate provider operation inferred |
| U8 / C8 | Credential references resolve through checked file custody, including exact UID-only ACLs for root-owned systemd delivery; fixed diagnostics and stripped parser environment; reader cannot select credential paths or read API state | Unsafe file/symlink/mode/change cases, reader SQL denial and active-token reflection canaries; no arbitrary encoded-secret detection or same-UID sandbox claim |
| U10 / C10 | Commit accepted page and continuation together; terminal page alone refreshes success; expose partial/failure; reject repeated cursors and exhausted cycle budget | Native interrupted/resumed pagination, transaction rollback, cross-tick loop and freshness cases; no snapshot completeness, watermark or absence-as-deletion inference |
| U12 / C12 | Bind installed parser/transport/database outcomes and both LTS delivery tests to the candidate before operational acceptance | Unit tests alone do not establish service credential delivery, provider entitlement, licence clearance or upstream API compatibility |

A relevant process-model error is treating possession of an API key as permission
for every downstream consumer. The implemented profile rejects narrower rights
instead of pretending existing shared storage/readers enforce them. Paid requests
are also rejected; an unmetered operator declaration is not independently verified
billing evidence. Failure/refusal preserves prior accepted pages and private
continuation rather than skipping missing records. Restore clears continuation
and disables acquisition pending reconciliation. Requests still disclose the
operator's queries to the upstream provider; query-disclosure policy and separately
isolated rights domains remain unfinished controls.


## Scheduled API service refinement

[ADR-0047](../adr/0047-scheduled-api-service.md) allocates U1/U4/U8/U10/U12 to
an opt-in one-source service: no implicit source discovery, checked loaded
credentials, unchanged public-destination/TLS admission, due/backoff-based
no-dispatch and explicit partial freshness. The collector UID remains a shared
trust boundary. A partial tick's zero exit code must not be interpreted as complete
source freshness. The guarded fixture cross-checks journal UID, HTTP observations,
private cursor/run state, immutable evidence and worker/reader postconditions;
ordinary parser tests do not replace candidate-bound two-LTS service evidence.
Actual providers, operational deployment and sustained capacity remain open.


## KEV format acquisition refinement

[ADR-0048](../adr/0048-kev-catalogue-adapter.md) refines the existing API
allocations without establishing exposure, regulatory applicability or upstream
authenticity merely from a compatible payload. Relevant process-model errors
include treating date-only fields as instants, a catalogue revision as a change
to every item, unknown fields as harmless, and missing items as withdrawals.

| Existing UCA | Constraint allocation | Discriminating evidence and limits |
| --- | --- | --- |
| U1/U4 | Endpoint remains private and explicit; source-selected links are inert; adapter selection grants no destination or execution authority | Authored fixtures, source/artifact/message scans and unchanged transport denial tests; no actual publisher-access claim |
| U8 | Existing checked credentials and exact reflection refusal apply to any configured mirror; no new secret channel | Existing credential/transport regressions; same-UID and arbitrary encoded-secret limits persist |
| U10 | Validate whole catalogue/count/identity/schema before admission; canonical per-entry text excludes release metadata; retain raw run evidence and absence ambiguity | Native TLS/SQL metadata replay, revisions, empty catalogue, atomic malformed refusal and generic-to-KEV continuation reset; no monotonic upstream revision guarantee |
| U12 | Bound parser and installed TLS/SQL/service evidence to the candidate; preserve dates and source assertions without inferring exposure or operator obligations | 1001-entry installed/native cases and disconnected two-LTS collector/worker/reader fixture; ceiling is not sustained production capacity or semantic-domain acceptance |

Refusal preserves accepted records and reports failure rather than accepting a
truncated catalogue. Optional action/triage fields remain source text; they do not
authorize remediation or forensic execution. Broader E31/E32/E40 controls need
qualified domain persistence, independent applicability and revision semantics.


## OAuth acquisition refinement

[ADR-0049](../adr/0049-oauth-client-credentials.md) allocates the existing API
constraints to two explicit destinations and two credential uses. Relevant
process-model errors are confusing authentication with content-use rights,
replaying resource rejection as a fresh grant, assuming a JWT's decoded claims
authenticate its issuer/audience, or resetting old progress because a new optional
configuration field changed serialization.

| Existing UCA | Constraint allocation | Discriminating evidence and limits |
| --- | --- | --- |
| U1/U4 | Both HTTPS endpoints remain private/operator-configured; client secret goes only to token endpoint, bearer only to resource; no redirect, discovery or arbitrary POST | Native distinct-origin TLS and exact request inspection; existing pinned-address denial cases; no actual provider contract inferred |
| U8 | Reuse checked secret custody; do not persist grant response or pass it into evidence parser; refuse exact raw/decoded resource reflection of either secret | Native SQL/CAS non-retention and reflection cases, real loaded-secret service exchange; no zeroization, arbitrary encoded-secret detection or same-UID sandbox |
| U10 | One grant and at most one resource request per admitted tick; expiry bounds transport; no authentication fallback or automatic refresh/replay; typed Retry-After preserves source backoff | Disabled/not-due/cycle-cap no-dispatch, rejection request counts, malformed/expired/scope-changed grants, native scheduling and two-LTS denial/recovery |
| U12 | Preserve old profile bytes; bind installed/native and real-service evidence to candidate; require independent provider/rights adoption | Exact legacy hash and compatible continuation cases, revision-bound service outcomes; asymmetric authentication, real entitlements and full E05/E08/E10 acceptance remain open |

The AS and resource remain separate trust boundaries even when privately
configured at one origin. Requested/returned scope is checked, but opaque-token
issuer/audience validation and remote enforcement are not invented locally.
Failure preserves prior accepted evidence and does not silently retry.

## Required runtime evidence refinement (ADR-0050)

SC5 and U12 apply to the declared required qualification set: 24.04/3.12 and
26.04/3.14. The release controller must reject a missing, failed, cancelled or
skipped required profile. Optional 3.13 evidence cannot replace either LTS set,
and optional/experimental artifacts are excluded from the isolated signer's
exact same-run set. Optional failures remain observable in their own workflow;
they are not converted into successful qualification. A dependency-only 3.15
probe cannot establish application support or widen installation bounds.
Discriminating checks execute the aggregate/profile-admission/signer scripts
against missing required, extra optional, substituted-runtime and corrupted-byte
fixtures; actual GitHub runs separately exercise required and optional routing.
See [ADR-0050](../adr/0050-required-lts-and-optional-python-profiles.md).

## Operator file-admission refinement

SC1/SC2/SC3/SC6 and existing C7/C43/C45 apply before a collector tick or explicit
text import reaches database/model work. Treating a private path as necessarily
bounded regular input was a process-model error: a FIFO blocked startup and an
oversized text file was fully allocated before validation. Fixed call-site
profiles now reuse no-follow/nonblocking regular-file admission, initial size
checks and bounded reads with growth refusal. Errors omit paths and payloads;
valid empty source configuration still reports non-execution before DB access.
Actual installed CLI special-file/refusal cases, exact UTF-8/byte bounds and a
native import-to-evidence/read round trip provide discriminating tests in
`tests/test_operator_input.py` and `tests/test_integration.py`.

The operator retains path authority; no source/MCP/model-selected path is added.
These are discrete admission actions. The guards do not impose physical
regular-file I/O deadlines, verify parent-directory custody or establish a
filesystem sandbox. Supervision and the rest of the tick's deadlines remain
separate controls. Full-scenario acceptance remains open.

## Active cloud credential reflection refinement

CA12/CA15 must not treat a schema-valid remote response as safe application data
when it echoes the active dispatch secret. Under SC1/SC3/SC7 and existing C8/C96/
C98, typed output strings and keys are checked after JSON decoding and before
assertion acceptance. Refusal emits only `REMOTE_CREDENTIAL_REFLECTED`; the
completed remote attempt preserves reported usage or reserved exposure and the
failed job is not replayed. Native TLS, ledger and zero-assertion cases include
literal/escaped echoes and reported/missing usage, alongside all credential
channels. The process-model error is equating valid schema with safe disclosure,
or treating refused application output as zero-cost remote non-execution.

No operational leak is established by the synthetic counterexample. This
backstop detects exact active-token occurrences, not arbitrary encodings, other
secrets or all personal information. Source classification and independently
accepted provider/data policies remain separate prerequisites.

## Assertion label-contract refinement

SC2/SC4 and U19/C19 distinguish a located quotation from a label occurrence,
entity resolution or semantic support. The v1 read envelope encouraged a faulty
process model by calling quotation-bound label hashes source mentions. Under
[ADR-0051](../adr/0051-honest-assertion-label-bindings.md), response v2 names them
label bindings and explicitly reports entity resolution as not performed.
No stronger extraction or reviewer authority is implied. Tests preserve hash
inputs and original evidence while exercising absent labels, empty responses,
role/source/span isolation and the actual stdio projection. Human interpretation,
independent review and full E27/E28 semantic acceptance remain open.

## Operator-controlled local API refinement

SC1/SC2/SC3/SC4/SC7 and existing inference/dispatch constraints apply when the
client cannot verify a local runtime PID or model file. Under
[ADR-0052](../adr/0052-local-inference-chat-api.md), explicit private-address
routing, verified TLS outside loopback HTTP, managed credentials, declared data
classes and qualification/no-forwarding/unmetered assertions prevent implicit
route selection. Endpoint locality does not establish sovereignty or absence of
cloud forwarding. Source/model input cannot select a destination or credential.

The unsafe control action is dispatching another operation after timeout/crash
without resolving possible ongoing API work. Persisting a secret-free API receipt
before POST blocks all cooperating local inference until recognized completion
or evidence-bound operator termination attestation. Health, caller timeout and job
cancellation are insufficient. An exclusive fsynced resolution record precedes
exact marker removal; conflicting/unsafe records remain blocked. Native/API
formats cannot clear each other's ownership. Normal completion, non-execution,
secret refusal, malformed/oversized/delayed responses, concurrent admission and
write-before-unlink recovery require discriminating tests. Full E34–E38/E41/E44
acceptance, operational deployment and independent reviewer authority remain open.

API resolution audit custody additionally checks file identity/size across fsync
and checks the named directory entry before marker release. Replacement,
truncation and same-size mutation on both new-write and existing-audit retry paths
must leave the uncertain reservation intact. These failure-injection cases cover
accidental substitution; the same-UID non-atomic custody limitation remains.

## Review authority and retrieval updates: ADR-0053

| Unsafe control action or nonexecution | Required constraint | Discriminating evidence |
| --- | --- | --- |
| A producer accepts its own proposal using a different actor string or assumed role | Separate reviewer credential; deny session/current writer membership; validate actual connection authority before append | Direct writer denial, accidental grants, non-inherited overlap and SET ROLE tests |
| An upgrade or restore treats a legacy writer decision as independently authenticated | Preserve history with legacy authority; exclude it from effective decisions; require fresh review and invalidate affected cited products | Actual core-11 upgrade, exact legacy/current checkpoint and stale-product tests |
| A reviewer rewrites evidence, proposals, jobs, earlier decisions or provenance | Explicit column INSERT only, database-stamped provenance/time, no producer or update authority; owner/recovery remain trusted | SQL permission negatives, broadened PUBLIC/login grants, revoked existing connection and private-reader tests |
| Valid review is refused after revocation, bad provisioning or unavailable database | Refuse without a new accepted review; preserve proposals and history; report a bounded error; provision credentials explicitly | Missing reviewer configuration and revoke tests; no writer fallback |
| A retrieval writer rewrites identity or corpus metadata while retaining a generation ID | Column-scoped UPDATE for status/error and active-generation pointer only | Actual catalog allowlist, denied identity UPDATE, existing activation/rollback/purge/recovery suites |

Separate credentials do not prove different humans, citation entailment or an
independent administrator. Promotion of learned workflows remains deferred; no
new autonomous policy mutation or experiment framework is introduced.

## Explicit chunk operations: ADR-0054

Under SC2/SC4/SC7 and C6/C9/C10/C12, CA4 job acceptance must distinguish immutable
replay from scheduling and chunk success from downstream completion. A faulty
process model treats re-import or cancellation as clearing terminal state, or
interprets an outbox row as completed enrichment. Explicit version-bound operation
identity preserves prior jobs; collectors do not gain downstream read/update
permissions merely to report acquisition. Transactional receipts must roll back
with chunk acceptance when the lease or commit guard fails.

Discriminating tests cover preserved failed/cancelled/succeeded originals,
concurrent same-operation identity, terminal downstream feedback, actual collector
permissions, final lease expiry and injected pre-commit failure. Historical-head
and retirement tests preserve lifecycle constraints. A different chunk operation
ID authorizes character computation only; it cannot resolve or replay uncertain
model/API/cloud execution. Full workflow scheduling, semantic quality and human
review acceptance remain outside this refinement.

## Frozen reranker diagnostics: ADR-0055

SC2/SC4 and C9/C12 apply to diagnostic scoring. A model score or completed run must
not be presented as supported interpretation, calibrated confidence or independent
quality acceptance. The rank-only profile retains unsupported questions and their
failed abstention gate. Complete-corpus scoring does not establish production
candidate recall, filtering or end-to-end retrieval quality.

The causal errors are rebinding mutable model configuration after freezing the
protocol, accepting scores for unsubmitted IDs, truncating judged text, or hiding
a late failure behind earlier successful systems. An owned manifest snapshot,
preflight complete-text bounds, exact ID/numeric correspondence and durable
per-query observations constrain these paths. Native CLI, model-tamper, identity
mismatch and caller-mutation cases discriminate the constraints. Unresolved
inference admission remains blocking; no automatic download, dispatch or learned
workflow promotion is introduced. Independent labels and adoption remain open.


### Encoder manifest custody correction: 2026-10-19

The same frozen-identity constraint applies to the ADR-0025 encoder path. A valid
caller mutation of a nested query template could previously change later native
calls while the initial protocol retained the old identity. The runner now owns a
deeply revalidated encoder configuration before output creation and records its
prediction identity from the frozen protocol. Native nested-mutation and invalid
nested-configuration counterexamples discriminate this correction. This does not
freeze files on disk: per-call byte-integrity checks still refuse later artifact
tampering and preserve partial observations. It does not establish model quality.


## Production index encoder custody: ADR-0056

SC2/SC4 and C9/C12 also constrain generation publication and hybrid reads. Capturing
a space identity while retaining a mutable caller-owned encoder can bind stored
vectors, metadata or query vectors to different semantic contracts. Constructor
custody now revalidates and owns the complete encoder configuration; generation
publication, activation compatibility and queries use that same contract. No
automatic reconfiguration or repair of old vectors follows.

Native numerical counterexamples distinguish original and changed templates.
Installed PostgreSQL cases check recorded manifest/dimensions, exact stored
vectors and fused query scores. Existing failed-build and purge-interleaving
cases retain their failure/admission assertions through the owned native client.
These bounds do not establish historical producer custody, useful pretrained
quality, workspace authorization or a sandbox against privileged code mutation.


The ADR-0056 registry follow-up also refuses a pre-existing space key whose stored
manifest or dimensions conflict with the owned contract. The check precedes
generation insertion/native work in the registration transaction. Native cases
retain the original row and assert zero new generations/active pointers. This
prevents a safe rebuild command from silently inheriting inconsistent metadata;
it does not authorize automatic repair of historical evidence.


The ADR-0056 active-generation follow-up extends registry comparison to activation,
status and hybrid search, including generation dimensions. Search refuses a known
conflict before native query dispatch, activation retains the old pointer and
status reports incompatible. A native PostgreSQL fault-injection case preserves
conflicting metadata and vectors while proving refusal and continued explicit
lexical access. A matching registry still cannot prove historical vector custody.


## Production read reranker custody: ADR-0057

SC2/SC4 and C9/C12 also constrain the identity returned with ranked read results.
A caller-owned mutable reranker could change scoring configuration after service
construction, and its reported identity could describe configuration different
from the child packet. The read service now owns a validated built-in client and
captured identity. Each rank call independently validates one manifest snapshot
before admission and derives packet and thread environment from it.

Installed native tests mutate configuration at admission while executing the real
ONNX child, and refuse invalid configuration before admission. PostgreSQL search
retains original identity and exact scores after caller mutation; existing MCP
transport coverage also exercises the reranked search response. The seven-read
surface, lifecycle fence and native admission/resource limits remain unchanged.
Historical responses are not requalified, and privileged in-process mutation,
pretrained relevance and workspace authorization remain outside this guarantee.
