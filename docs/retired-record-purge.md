# Retired-record SQL purge

This explicit maintenance command deletes a retired logical item's rows and known
derivatives from the current PostgreSQL dataset. It does not perform physical
media erasure, remove CAS files, expire backups or remove previously disclosed
copies. It is separate from logical retirement and orphan-object GC.

## Authority and upgrade

Install core migration 7 and, if configured, retrieval-profile migration 3 using
the existing explicit migration commands. Retrieval-profile migration 4 later adds
purger SELECT/DELETE on `ow.retrieval_exclusions`. Published earlier migrations are
unchanged. Checkpoint format 2 and lifecycle-policy format 1 keep their data layout;
the new `purge` event extends the accepted event vocabulary. Earlier binaries
cannot validate that event and must not operate a dataset after adoption.

Provision a dedicated non-owner login with membership only in the `ow_purger`
application group. Supply its credential outside source control as `OW_PURGE_DSN`.
The migrations grant the group's exact maintenance privileges. The command checks
effective privileges, reachable roles, ownership, delegation, schema history and
full row visibility. Writer, reader, collector, ordinary lifecycle and superuser
identities are refused. No existing worker or MCP reader receives purge authority.
The role can directly delete rows if its credential is used outside this program;
this is an operator boundary, not row-level capability confinement.

Quiesce affected workers before planning. The reference implementation captures
at most 10000 total rows and 16 MiB of serialized metadata across its known core
and optional profile. A plan envelope is at most 4 MiB. The inventory includes all
rows, so even an unrelated accepted mutation makes a plan stale. Counts and byte
limits bound this reference profile; they are not whole-command time or memory
proofs. Existing database statement and lifecycle-lock timeouts remain active.

The inventory includes remote accounting attempts, keyed by `attempt_id`, in
every state including denied and settled. Purge never deletes or updates those
rows; changes to them invalidate a prior plan like other inventory changes.
Their inclusion does not imply erasure of accounting or provider records.

## Plan and apply

First place and verify the permanent logical-retirement decision using the
existing lifecycle command. Expiry alone never authorizes purge. Select any
retained document version of that logical item; the plan covers every version
with the same source and external key.

```sh
osint-workbench purge plan --document-id "$DOCUMENT_ID" \
  --operation-id "$OPERATION_ID" --actor "$ACTOR" --rationale "$RATIONALE" \
  --file "$PRIVATE_PLAN"
```

The plan is a private, no-overwrite, mode-0600 artifact. Its canonical digest binds
actor, rationale, operation, dataset, policy revision, exact migration/profile
history, complete inventory digest and each affected primary key/row digest.
Review the plan with private tooling. In particular, inspect whole briefings that
will be deleted, retained shared snapshots, generation invalidations and retained
collection references. A digest proves agreement with reviewed bytes/structure;
it does not supply authorization, independent custody or semantic completeness.

```sh
osint-workbench purge apply --file "$PRIVATE_PLAN" --sha256 "$REVIEWED_DIGEST"
```

Apply recomputes the plan under exclusive cooperative lifecycle admission. It
refuses stale inventory, active preservation holds, held collateral products,
unknown/malformed briefing contracts, inconsistent cross-item references,
unsupported schema dependencies or broadened operator authority.

All deletions, generation invalidation, policy revision increment and the `purge`
event commit in one database transaction. A failed delete rolls back the event
and all preceding deletes. A lost commit acknowledgement is an uncertain command
outcome; retry the exact plan and digest. A matching durable event returns its
stored result with `replayed: true`. An operation/digest conflict is refused.
A replay reports the recorded decision; it is not a new deletion. Keep the private
plan and independently export/custody the latest lifecycle policy and its digest.
Never infer completion from missing rows or a pre-commit external completion file.

Replay still requires the current supported authority, schema, policy and bounded
inventory, including absence of reintroduced purged content. Unrelated growth
beyond this profile or changed admission can prevent the replay command from
reaching the stored event. Preserve the uncertain outcome and reconcile the
durable event with trusted maintenance authority; do not bypass those checks or
infer rollback. A separate bounded historical-receipt query remains future work.

## Deletion closure and retained data

The command removes target heads/documents/chunks, associated enrichments,
assertions/reviews, linked jobs/events and whole immutable briefings that select
or cite the target. Shared briefings containing any actively held neighbour veto
the operation; they are never silently rewritten. Shared snapshots survive when
any other document still references them. Sources, collection runs/state, lifecycle
items, holds, tombstones and decision events remain.

Remote-attempt ledger rows (core v9, settlements from v10) are retained: they hold route, policy and
packet digests with accounting, not document identifiers or content, and their
exposure must survive purge. The purger may only read them for its exact
authority checks. Purge still refuses any non-internal trigger or rule in the
`ow` schema, with one reviewed exception: the ledger's `remote_operation_transition`
trigger, accepted only while it fires per row before UPDATE on
`ow.remote_operations`, which purge never modifies.

For optional retrieval, only target vectors, exclusions and members are deleted.
Purge events recorded under profile 4 carry a `retrieval_exclusions` count;
earlier events without that key remain valid. Affected
generations are marked failed with `RETIRED_RECORD_PURGED`; their active alias is
removed. Other members/vectors and generation/corpus identities remain. Hybrid
retrieval therefore needs an explicitly rebuilt and activated compatible generation.
This availability consequence appears in the plan. A late builder cannot promote
an invalidated generation back to ready. Lexical reads of surviving documents
remain available.

Purge removes linked job-event history as part of the content closure; the
permanent lifecycle retirement and purge decisions remain as the audit record.
Arbitrary references buried in free-form text, unknown job payloads/results,
external files, process memory and future application profiles are not a proven
semantic deletion closure. Such profiles need explicit reference contracts before
claiming complete erasure. The command neither searches all text for identifiers
nor claims that opaque hashes establish anonymization.

CAS files are untouched. Shared feed bytes can remain referenced by a surviving
snapshot, collection receipt or validator state, and may still contain the retired
material. Existing separately planned orphan GC can later remove only objects
that have become unreferenced and satisfy its age/identity rules. SQL deletion
also leaves PostgreSQL dead tuples, WAL, replicas and storage recovery questions
outside this command. Retained policy identifiers and rationale remain private data.

## Recovery and reversibility

Latest trusted lifecycle policy containing a purge decision causes restore to
reject any checkpoint with matching source/external-key documents, before object
root creation or metadata acceptance. It does not silently strip a historical
checkpoint or attest destruction of that checkpoint. A post-purge checkpoint can
restore the reduced SQL state; retained raw feeds can still contain the material.

Exact known core-v4/v5/v6 checkpoints with the supported old optional profile may
be adopted into the new schema only if their full migration/data contracts match
and current policy permits their contents. Unknown or mixed histories fail closed.
A joint rollback of checkpoint, policy, digest and trusted minimum revision remains
undetectable offline; independent policy custody remains an operator obligation.

There is no ordinary undelete after a confirmed purge. Reverting application code
or selecting an old checkpoint is not a rollback procedure for the deletion
policy. Stop the operation on failed admission, preserve the plan/receipt, and
resolve the failure before replanning. Full copy expiry, raw-feed disentanglement,
secure media erasure and complete E48 acceptance remain outstanding.
