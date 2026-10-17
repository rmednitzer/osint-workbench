> Target specification. See STATUS.md for implemented and verified scope.

# Bounded STPA analysis

## Purpose, boundary and method

Analyze loss of privacy, evidence integrity, service utility and operator trust during extraction, operation and publication. This is a proposed system-level analysis for an information-processing reference implementation, not a physical safety certification or a quantitative risk assessment. Method reference: Leveson and Thomas, STPA Handbook, March 2018, chapters 2-3 [S1]. Complement it with STRIDE threats at trust boundaries rather than treating STPA as a substitute for code security review.

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

This covers the complete proposed profile boundary and publication lifecycle. It does not prove completeness, source truth, independent publisher corroboration, hostile model resistance or multi-tenant isolation. The remote transport profile is included under ADR-0017; future unregistered adapters require a new authority review. The ML/claims/cloud/lifecycle extensions below are part of this revision, not deferred scope. Stop release if a safety/security constraint lacks implementation allocation or mandatory verification evidence. A second human review of the model is recommended where available, but no independent review has occurred in this planning task.


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
| Promote a schema-valid model statement solely because some quoted text exists | Preserve typed proposals, exact source spans and polarity; require an independent operator review before cited factual products | `test_proposals_review_cited_product_rejection_and_source_updates`, invalid-result and abstention tests |
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

Retention/holds/tombstones, old-host computation ownership, source re-enablement,
external effect reconciliation and host-level configuration recovery remain open.
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
| U34: acknowledge an unchanged response without intact accepted local evidence, or advance a validator after partial acceptance | C34: bind validators to URI/profile, verify retained raw evidence, commit validators only with completed acceptance | Real 200/304 framing, lost-cache fallback and partial-run replay tests |
| U35: send source-specific validators to another redirect resource or retain them after configuration/restore changes | C35: strip on redirects, reset on resource change and isolated restore, deny SQL/MCP access | Redirect, changed-resource, scoped-reader and recovery tests |
| U36: restart collection without retaining retry delay, dispatch unbounded work or hide independent sources after one failure | C36: reserve due state before dispatch, bound backoff/counter/tick size, retain per-source failure feedback | Killed collector, restart, bounded tick/backoff and independent-source tests |

No timer deployment, global host quota, Retry-After enforcement or complete
acquisition acceptance is implied. A freshness success means representation
validation, not factual currency or independently verified content.
