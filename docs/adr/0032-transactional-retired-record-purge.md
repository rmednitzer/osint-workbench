# ADR-0032: Commit retired-record purge and its durable decision together

Status: ACCEPTED for implementation; revision-bound execution evidence pending.
Owner: maintainer. Date: 2026-10-17.

## Context and requirements

Logical retirement prevents serving and new processing but retains document
bodies and derivatives. Orphan-object cleanup preserves every database reference
and cannot remove these records. CA17/C21 therefore needs an explicit bounded
record-deletion operation, with holds, shared dependencies, concurrent acceptance
and historical recovery treated together. This contributes to the retention and
recovery programme; it does not establish complete erasure or close E39/E48.

The unit is an already permanently retired `(source_id, SHA256(external_id))`,
including all document versions. Expiry alone is insufficient authority. The
permanent policy identity, tombstone, holds and decision history survive deletion;
they remain private records and prevent ordinary reingestion under that identity.
Another source/key or semantic copy requires its own disposition.

## Alternatives and decision

| Alternative | Benefit | Cost and boundary |
| --- | --- | --- |
| No change; retain logical suppression and orphan GC | Existing recovery formats and authority remain unchanged | Retired bodies and derivatives remain indefinitely; no record-purge capability |
| Impact plan only | Makes dependencies and collateral effects reviewable without deletion | Cannot fulfil a request to remove retained records |
| SQL deletion with only an external intent/completion journal | No schema change; private reviewed intent can precede deletion | Database commit and receipt cannot be atomic; existing restore cannot infer prior purge and may recover hidden physical records |
| Durable purge decision in lifecycle history, atomic with SQL deletion | Replay has a database authority; current policy can prevent historical resurrection | Requires an additive migration, policy validation changes, strict restore compatibility and independently retained current policy |

Choose the durable decision. Core migration 7 adds `purge` to the existing
lifecycle-event action vocabulary and provisions a separate `ow_purger` authority.
Retrieval profile 3 adds the corresponding optional-profile authority. Published
migrations remain immutable. No tables or columns are added; checkpoint format 2
and policy format 1 retain their layouts, but their accepted semantics expand.
Older binaries that cannot validate a purge action are not recovery tools for
this state. Exact known core4/5/6 and retrieval2 histories require deliberate
tested adoption into core7/profile3; unknown or mixed histories fail closed.

## Reviewed scope and dependency closure

A bounded private impact plan binds operation identity and digest, dataset UUID,
policy revision, exact supported schema/profile history, target identity and the
affected record/dependency set. Counts alone cannot identify a changed plan.
Apply recomputes the relevant state before mutation and refuses stale or
unsupported dependencies. Plans and receipts use private restricted files,
no-overwrite publication and safe public errors; they are not public exports,
signed attestations or protection against replacement of both file and trusted
digest.

Delete the target versions' chunks, assertion reviews/assertions, enrichments,
associated jobs/events, heads and documents in foreign-key-safe order. Include
both explicit document references and supported transitive references. A snapshot
is eligible only when no surviving document references it. Shared immutable
briefings containing the target are removed whole, with their collateral impact
listed; do not rewrite content beneath an existing product hash. A product shared
with an actively held neighbour must block the operation. Unknown or inconsistent
reference shapes must not silently pass as an empty dependency set.

For affected retrieval generations, remove target vectors/members, invalidate
the generation and remove its active alias while preserving neighbouring evidence
and vectors. Do not relabel the remaining subset with the old ready-corpus claim.
An already running builder must not overwrite invalidation with an unconditional
ready update. Generation acceptance and per-document acceptance must remain
consistent with lifecycle visibility and generation state.

Sources, collection receipts/cache state, embedding-space identities and lifecycle
history are outside the deletion set. Shared raw feeds may still contain target
text. Retained snapshots, collection runs and cached-body references continue to
protect their CAS objects. Any subsequent orphan GC is separately planned and
reference-checked; this operation does not remove CAS bytes by guessing ownership
from their contents.

## Authority, transaction and replay

Use an explicitly provisioned separate DSN and `ow_purger` role, with the fixed
SELECT/DELETE and narrowly required lifecycle/retrieval update/insert authority.
Reject superuser, object-owner, writer or collector authority instead of silently
falling back. No purge tool is added to MCP. Optional retrieval authority is
required when its supported profile is installed; disabling a runtime feature
does not remove stored dependencies from the closure.

Acquire the existing exclusive lifecycle session lock before taking the mutation
snapshot. Recheck tombstone, holds, policy revision and the full relevant impact
set under that exclusion. Runtime producers, readers, job acceptance and
generation activation share admission; their operations either precede purge or
observe its committed state. An old job fence must not recreate deleted rows.
This is cooperative database coordination, not exclusion of old binaries,
arbitrary privileged SQL, filesystem writers or previously returned client data.
Long admitted work may cause bounded `LIFECYCLE_BUSY`; do not report success or
force deletion through it.

The purge event, revision advance and SQL deletions commit in one transaction.
The event stores the request/plan binding and bounded outcome needed for exact
operation replay. Reusing an operation ID with another request/plan fails. A
response lost at COMMIT is an error with uncertain outcome; an explicit retry
queries the durable event and either returns the exact committed result or
performs the still-authorized transaction. An external completion file is a copy
of that result, never authority to assume commit happened. Filesystem publication
failure after commit does not roll the database decision back.

## Recovery and irreversibility

The independent current policy export now carries purge decisions. Restore
reconciles dataset lineage, trusted minimum revision and complete policy history.
When current policy says a key was purged, a historical checkpoint containing its
records must be rejected before object acceptance; a tombstone that merely hides
restored bytes is insufficient. A checkpoint taken after purge remains eligible
when the supported schema, policy and provenance checks pass. Restore does not
silently prune an old bundle, discard its objects or reinterpret an unsupported
history as a compatible one.

Deletion is irreversible through the supported API. A failed transaction rolls
back its event and deletions together; committed deletion has no unpurge command.
Reverting the binary does not undo the migration or restore deleted rows, and an
older binary is not safe rollback after the new decision vocabulary is used.
Retain the newer maintenance/recovery tool and current policy custody. A separate
historical checkpoint remains sensitive retained data, not an authorized means
to reintroduce purged records. Losing or jointly rolling back policy and its
trusted freshness receipt defeats offline knowledge of the decision.

SQL deletion does not establish removal from PostgreSQL dead tuples, WAL, physical
backups, replicas, exported products, model memory, remote copies or storage media.
Shared snapshots/feeds and necessary policy history may retain information.
Backup expiry, media sanitization, semantic duplicate discovery and whole-host
recovery require separate controls and evidence. No legal compliance or global
erasure claim follows from a successful transaction.

## Required verification

Require installed-wheel native PostgreSQL evidence for all-version closure,
held/shared collateral, stale-plan refusal, least-privilege and negative authority,
rollback partway through mutation, exact replay and changed-operation refusal,
job fences, concurrent retrieval building/activation, direct SQL/MCP absence and
suppressed reingestion. Exercise core-only and retrieval installations, retained
schema upgrades, exact historical adoption, post-purge checkpoint restore and
pre-purge rejection before object acceptance. Private plans/receipts and public
diagnostics need failure/redaction tests. Until a revision-bound receipt records
execution, these are acceptance obligations rather than verified completion.
