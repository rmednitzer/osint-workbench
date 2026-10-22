# ADR-0064: Artifact continuity, bounded evidence and worker authority

Status: implemented; hosted and operational qualification remain separate.

## Context and drivers

The security scan of revision `07118242c8322609097ae06ea98bce51f9306eff`
identified mutable tested distributions, ambiguous archive inspection, cumulative
CAS growth, generic runtime writer authority and provider-controlled exposure
reduction. The drivers are byte identity across CI jobs, bounded persistent
allocation, component isolation, immutable operation identity and conservative
admission. Source findings do not establish an operational compromise.

## Alternatives and decision

| Option | Consequence | Decision |
| --- | --- | --- |
| No change | Retains the observed integrity, resource and privilege gaps | Rejected |
| Hash distributions only inside the test job | Same process authority can replace bytes and their hashes | Rejected |
| Immutable build artifact before tests, fresh-runner continuity checks | Separates original bytes from test execution; signing compares originals again | Selected |
| Per-object limits and operator GC only | Referenced changed containers can still grow without a cumulative bound | Rejected |
| Serialized store byte/object admission plus external filesystem quotas | Bounds cooperative CAS growth; database/WAL and hostile same-UID writers remain external | Selected |
| Generic producer credentials in services | One compromised worker can mutate sibling work and accounting | Rejected |
| Distinct chunk, local enrichment and dispatcher capabilities | Additive schema and credential provisioning; database guards bind mutations to kind and login | Selected |
| Provider usage immediately releases reservation | Spending counterparty controls later admission balance | Rejected |
| Retain reservations until separate evidence-bound settlement | Conservative capacity can exhaust sooner and requires operator reconciliation | Selected |

Archive inspection uses physical ZIP entries, rejects ambiguous paths, duplicate
names, links/special entries and unsupported ZIP extras, and scans supported names,
comments and tar/PAX text metadata. It remains a backstop, not exhaustive DLP or
an arbitrary binary-container classifier.

## Authority and limits

Core schema 13 adds runtime capabilities without changing published migrations.
`ow_writer` remains a trusted operator producer capability, not a service login.
Chunk workers use `OW_CHUNK_DSN`; local enrichment uses `OW_ENRICHMENT_DSN`;
governed generation uses `OW_DISPATCH_DSN`. No fallback to the operator DSN is
permitted. Administrator-owned `ow.worker_kinds` binds an enrichment login to an
exact generator kind and local/remote execution class. Worker jobs preserve
identity/payload and terminal state, and active leases bind to the claiming login.
Remote attempts bind to the inserting database login. A different dispatcher
cannot release them. Dispatcher compromise can still falsify its own transport
outcome; SQL cannot independently observe whether network bytes were sent.

Runtime capabilities retain read visibility into the job queue; these guards
constrain mutations, not per-component confidentiality or tenancy. Operators,
database owners, recovery and superusers remain trusted. Explicit producer
commands can enqueue work; worker timers do not acquire producer credentials.
The optional vector builder remains an operator command, not a deployed worker.

`EvidenceStore` defaults to a 1 GiB logical-byte ceiling and 100000 objects as
library safety bounds. CLI operators can select `OW_EVIDENCE_MAX_BYTES`; this is
not a capacity recommendation or SLO. Writers serialize allocation on a private
lock file and count existing regular CAS objects before creating staging bytes.
Unknown entries fail closed. Exact existing objects remain reusable at the cap.
Filesystem metadata, PostgreSQL/WAL, backups, noncooperating processes and physical
block allocation require independent quotas and monitoring. No data is evicted
automatically. Inventory scans are bounded and linear in retained object count.

## Verification

Regression coverage includes distribution substitution with a rewritten receipt,
duplicate ZIP members and metadata canaries, cumulative bytes and competing store
writers, direct SQL under actual component logins, job/attempt ownership and
conservative usage admission. Native PostgreSQL, both required installed runtime
profiles, recovery/purge and actual disposable service acceptance remain distinct
from source and unit checks. Current results belong in STATUS and CI receipts.

## Blast radius and rollback

CI changes affect build/test/signing jobs; runtime changes affect writable CAS
operations, worker credentials, migration, recovery and cloud reservation capacity.
Provision separate credentials and generator-kind assignments before starting the
new worker binary. Quiesce workers before migrating. Existing running jobs have
no authenticated owner and can be reclaimed after lease expiry; old ledger rows
remain conservatively retained and can be settled by accounting.

Schema 12 checkpoints are admitted only with their exact published core/profile
history; new ownership fields are adopted as unknown. Worker-kind assignments are
independent deployment authority and are not checkpoint contents. Reprovision
those assignments on a recovery target. Never infer authority from archived jobs.

Rollback requires the matching old binary and pre-migration database checkpoint
plus independently current lifecycle policy, restored into an isolated target.
Do not delete migration 13, edit historical migration hashes or run an older
binary against newer state. CI changes can be reverted independently. Keep CAS
objects intact; increasing a budget is an explicit operator capacity decision.
