# Bounded orphan-object cleanup

This operator-only feature removes old, unreferenced immutable CAS files. It does
not purge document records, derivative history, held evidence, expired/retired
snapshots, shared raw feeds, backups, models or inference receipts. It establishes
neither physical media sanitization nor a right-to-erasure outcome. See ADR-0022.

## Authority and assumptions

`OW_GC_DSN` must identify a trusted maintenance principal with `ow_lifecycle`
membership and explicit SELECT on `ow.lifecycle_control`, `ow.migrations`,
`ow.snapshots`, `ow.collection_runs`, `ow.collection_state` and, when installed,
`ow.retrieval_migrations`. No runtime role is automatically granted these extra
privileges. The filesystem identity must have read/unlink permission on the
private evidence store and write permission on the private plan/journal parent.
Do not give MCP or ordinary collectors these credentials or filesystem rights.

All application writers, checkpoint/restore operations and lifecycle changes must
use the current cooperative lifecycle barrier. Stop old binaries and independent
SQL/filesystem writers first. A malicious or privileged actor changing directory
entries concurrently is outside this contract; descriptor-relative no-follow IO
and identity/hash checks do not make unlink atomic against such an actor.
The operator must select the matching database/store pair. Dataset and inode
binding detect substitution after planning, not an initially misconfigured pair.

GC now also takes an exclusive `flock` on the opened store-root directory inode
before its final reference capture. Current ingestion, collection (including 304
reuse) and restore retain shared store admission through metadata commit and
connection close. The fixed acquisition order is database admission, then store
admission. A dead database backend cannot release the process's filesystem lock;
a waiting writer proceeds only after GC releases it, recreating any needed bytes
before accepting metadata. The filesystem wait is bounded to 5 s and reports
`EVIDENCE_STORE_BUSY`. Nested operations reuse only the same instance/thread's
anchored admission; another thread or process must acquire its own lock.

This protocol requires all producers to run the new code and a single authoritative
database/store pair on the supported local Linux filesystem. There is no unlocked
fallback, independent remote-filesystem acceptance or protection from a privileged
writer bypassing admission. Quiesce old processes before upgrade; downgrade while
GC or new acceptance is active is unsupported. See
[ADR-0033](adr/0033-durable-store-admission.md) for the failure model and rollback.

## Review and apply

Set `OW_EVIDENCE_ROOT` externally. Keep plans and journal directories outside the
store and outside Git, with private custody. They contain object hashes and
filesystem identities. Minimum object age defaults to one day and cannot be less
than one hour. No download, collection, inference or network-provider action occurs.

```sh
osint-workbench gc plan --file private/cleanup.owgc --operation-id cleanup-001
```

Review the JSON plan's candidates, counts and byte sizes against the intended
private store. Retain the returned payload SHA-256 independently. It hashes the
sorted-key JSON payload, not the envelope's raw file bytes. The hash detects
changed inputs; it is not a signature or an authorization system.

```sh
osint-workbench gc apply --file private/cleanup.owgc \
  --sha256 "$REVIEWED_PLAN_SHA256" --journal private/cleanup-journal
```

Both phases take the exclusive lifecycle barrier before their database snapshot.
Reachability uses **every** raw/text snapshot and every collection-run raw hash,
including historical, failed, retired and held records, plus cached-body pointers. Optional retrieval state
references documents rather than new CAS objects, so inactive generations retain
those documents' evidence too. Unknown schema tables/migration hashes and enabled
row security on reference tables fail closed. A changed reference set or policy
revision requires a new review; adding a hold cannot be silently ignored.

Scanning is streaming and limited to 10,000 total directory entries (shards count
too), 100,000 distinct references and 64 MiB of candidate data. Objects are bounded
to 20 MiB. Unexpected names, staging leftovers, symlinks, hardlinks, non-regular
files, cross-device objects and integrity mismatches require investigation; no
implicit cleanup of those entries occurs. Recent/future-dated objects are retained.
Plans and receipts are created with mode 0600, journals with mode 0700, without
replacing existing files. Existing parent directory permissions remain the
operator's responsibility.

## Failure and recovery

Before any unlink, apply rechecks every candidate and durably records an intent
bound to the reviewed plan hash. It then rechecks each file, unlinks it and fsyncs
its shard. A completion receipt is promoted only after all shard fsyncs succeed.
No database records are deleted or modified, and no database rollback can undo
an unlink. Completion counts describe the planned objects made absent, not proof
that this invocation removed every byte or reclaimed physical disk blocks.

After a crash or durability error, retain the plan and original journal and run
the same apply command. Missing candidates are allowed only with that matching
persisted intent. Existing candidates must still match identity and hash. Resume
fsyncs shards even for absent candidates before recording completion. No new
journal may authorize missing files. Corrupt, missing or partially created intent
requires manual investigation; do not fabricate or repair receipts to force a
resume. A changed policy/reference set blocks even a resumed operation. Replan
remaining orphans after investigating the partial outcome; prior unlinks are
already irreversible and do not affect retained database evidence.

Never remove journals merely because an invocation failed. A completion receipt
is historical evidence of the checked operation, not a continuous absence monitor.
Full record purge, backup expiry, staging-file recovery, distributed coordination,
physical storage sanitization and automatic scheduling remain outstanding.
