# Private checkpoint and isolated recovery

Format 2 is a bounded logical checkpoint of the workbench's `ow` application tables
and their referenced immutable evidence. It is **private data**, not a public
export. It contains source identifiers, document contents, job payloads, reviewer
identities/rationales, accounting/settlement metadata and stored products. Do not
commit, publish or send it to an AI provider. `.owcp` files are ignored by Git as
an additional backstop.

The file is not encrypted or signed. Store it on operator-managed encrypted storage
with restricted access, and keep its returned SHA-256 receipt separately in a
trusted location. Replacing both the file and the trusted digest defeats the
integrity check. No claim of anonymity, secure erasure or disaster recovery for
the whole host is made.
The returned `sha256` identifies the project's sorted-key JSON payload, excluding
the outer envelope. Use that receipt for `--sha256`; it is not the raw-file digest
reported by `sha256sum`.

## Capture contract

`checkpoint` uses one PostgreSQL repeatable-read, read-only transaction. Migration
history must match packaged migrations and every application table must be
classified. Row-level security on any application table is unsupported and causes
checkpoint or restore to fail before publishing a file or accepting target data,
even when the maintenance owner could bypass that filtering. A migration advisory lock excludes application migrations. Records
committed after the MVCC snapshot are excluded; this is not zero-data-loss backup
or WAL/PITR. A timestamp identifies capture transaction start, not completion or
the last accepted source event. See PostgreSQL's
[transaction isolation contract](https://www.postgresql.org/docs/18/transaction-iso.html).

All raw/text evidence referenced by snapshots, collection runs and private cached-body
pointers is read through
the integrity-checking store. Unreferenced files are excluded. Accepted ingestion
already makes objects durable before committing metadata, so the snapshot cannot
include a partially accepted document. Document bodies, chunk/vector coordinates,
assertion quotes and stored briefing hashes are checked. A concurrent deletion or
damaged object makes capture fail; no final file is published. Current runtime/checkpoint sessions share lifecycle admission; reviewed orphan
cleanup takes exclusive admission and rechecks every retained reference. Independent
SQL/filesystem writers and old binaries remain outside this cooperative contract.

Checkpoint holds shared store-inode admission while reading its objects. Restore
holds it from the new root's first object write through metadata commit and
connection close, including failed commit cleanup. GC takes exclusive admission
before its final reference snapshot. The consistent order is database, then store;
never reconnect or reacquire database admission while holding a store barrier.
This local Linux cooperative protocol depends on the matching database/store pair
and current binaries; see [ADR-0033](adr/0033-durable-store-admission.md).

Limits are 100,000 rows across all application tables, 32 MiB row metadata, 64 MiB
referenced object bytes and 128 MiB total file. This in-memory reference profile
rejects larger datasets; it is not a streaming large-corpus backup. Output uses a
new 0600 file, fsync and no-overwrite promotion. Partial private staging files may
remain after process/host failure and require operator inspection.

Core storage, all document versions/heads, collection receipts, jobs/events,
chunks, enrichments, assertions/reviews, briefings and remote-attempt ledger rows
(including settlements) are included. When installed, the exact retrieval
profile's spaces, generations, members, exclusions, vectors and active alias are
included. Generated full-text vectors are rebuilt by PostgreSQL. Prompt/response
and settlement-evidence digests are retained metadata; they do not cause the
referenced external files or provider records to be fetched or bundled.

Credentials, database roles/grants, source URL catalogs, external routing policy,
inference ownership receipts, model/tokenizer binaries and host/deployment
configuration, provider invoices and private settlement-evidence files are outside
the bundle. Protect and recover them separately. A
checkpoint is insufficient to reconstruct the whole installation.

The checkpoint includes its dataset UUID, retention, holds, tombstones and audit
events. Captured lifecycle state is not sufficient authority to restore: a separately
retained current policy and trusted receipt are mandatory. See
[lifecycle controls](lifecycle.md) for semantics, custody and legacy compatibility.

## Operator procedure

Run only on the installation you intend to back up. Set `OW_RECOVERY_DSN` privately
to an operator identity able to read every application table; the normal reader
intentionally lacks that authority. Set `OW_EVIDENCE_ROOT` to its evidence store.
The output's parent directory must already exist on private storage.

```sh
osint-workbench checkpoint --file /private-storage/checkpoint.owcp
```

Retain the returned digest independently. Test recovery before relying on the
file. Writes accepted after capture are outside its recovery point; account for
them explicitly through an operator-selected replay or later checkpoint.

Provision a **fresh isolated database**, with no collectors, workers or clients
connected. Use the matching application/lock version, PostgreSQL major version
and, where present, pgvector extension version. Provision separate login roles and
run the existing core migrations; also run `migrate-retrieval` when the source
profile included retrieval. Restore does not execute DDL/SQL supplied by a bundle
and never imports credentials or database grants.

Set `OW_RECOVERY_DSN` to the isolated target's operator identity and
`OW_EVIDENCE_ROOT` to an **absent** directory whose private parent already exists.
The target application tables must be empty apart from the migration's fresh
revision-zero control row. Set `CHECKPOINT_SHA256`, `POLICY_SHA256` and
`MINIMUM_POLICY_REVISION` from independently retained trusted receipts. Current
policy must belong to the checkpoint's dataset and cover at least its captured
revision and the independently retained minimum. Export it after lifecycle changes
using the operator-only `lifecycle export-policy` command.

```sh
osint-workbench restore --file /private-storage/checkpoint.owcp --sha256 "$CHECKPOINT_SHA256" --policy-file /private-storage/current.owpolicy --policy-sha256 "$POLICY_SHA256" --minimum-policy-revision "$MINIMUM_POLICY_REVISION"
```

Restore locks target tables, verifies compatibility and the expected digest,
validates all object bytes/provenance and policy history/state, stores objects durably and inserts metadata
in one database transaction using fixed table names and bound JSON values. No
bundle path, SQL statement, model download or network request is executed.
Preserved review/event identities remain ordered and their sequences advance.
Current retention, holds and monotonic tombstones override captured policy before
the metadata transaction commits. Reader views cannot serve retired/expired
records, their assertions/products or their vector candidates after restore. Their
private physical bytes remain retained; this is not erasure.
Any validation/constraint failure rolls back database records. A failed or killed
attempt may leave a private object directory; do not reuse it or delete it
automatically. Inspect and move it aside before a fresh attempt. If acknowledgement
is lost after commit, inspect the target's IDs/counts and read behaviour; retrying
against a populated target is deliberately refused.

All source rows become disabled. Ready/running jobs become failed with
`RECOVERY_RECONCILIATION_REQUIRED` and an appended event; historical fences cannot
accept completions. Running collection receipts become interrupted and incomplete
vector builds become failed. Completed records and compatible active retrieval
generations are preserved. Remote attempts retain their recorded statuses,
reservations, costs and settlements; restore neither releases uncertain exposure
nor automatically retries an operation. These changes are intentional recovery
dispositions, not byte-for-byte resurrection of a running process.

Before connecting consumers, check representative old/current document IDs,
evidence hashes, review states, cited products and search through the actual reader
and MCP client. Inspect stale products and degraded retrieval explicitly. Restore
the correct private model configuration and verify its identities before hybrid
reads. Keep cloud routing disabled until provider/accounting state has been
reconciled separately. The restored ledger reflects the checkpoint, not attempts,
charges or settlements recorded after it; a matching hash cannot recover those
external facts. Reconcile ownership of any computation still running on an old
host; a restored job cannot prove that computation has stopped. Reconcile external
effects and additional deployment-specific policy before enabling sources or
submitting explicit new operations. Keep external supervisors stopped: an explicit
`collect` with an enabled private configuration updates the source row and can
re-enable collection. Disabled restored rows are not a fleet-wide interlock.
There is no overall deployment readiness gate, all-copy erasure, cross-host
reconciliation or general operator command to resume quarantined work. The
separate [transactional SQL purge](retired-record-purge.md) is implemented within
its retired-record dependency closure; it is not a deployment readiness gate.

## Verification boundary

`tests/test_recovery.py` exercises fresh disposable PostgreSQL databases, a real
MCP stdio client, reviewed products and withdrawal after recovery, preserved
identity sequences, concurrent acceptance exclusion, native ONNX/pgvector hybrid
reads, core-only CLI round trips, corrupted objects/metadata, foreign-key rollback,
unknown tables, resource limits, symlink/no-overwrite and non-regular-file rejection.
The CI receipt applies only to its named revision. There are no operational data,
cross-major restore, encrypted-backup service, PITR, host-loss exercise or complete
lifecycle acceptance claims. Format-1 checkpoints require their previous isolated
tool/schema pair; they are rejected here, not silently assigned a new policy lineage.
Full consumer export and outbound publishing remain pending.

Core v5 includes private collection schedules and validator state. Restore clears
validators, cache pointers and failure/due state before acceptance and leaves
sources disabled. Exact core-v4/profile-v2 format-2 layouts may adopt an empty
schedule and unknown historical HTTP status into the current layout; unknown
migrations/layouts still fail closed. This does not enable core-v3/format-1 adoption.

Core v6 adds a collector role and a fixed `document.accepted` outbox default,
without changing checkpoint table layouts. Exact published core-v5 format-2
migration/profile hashes can be adopted under the same independent current-policy
checks; exact v4 normalization remains supported. Mixed, modified or incomplete
histories are rejected. Restore does not provision an operational login or enable
sources. Provision and validate the separate collector principal after recovery.

The current supported layout is core v11 and, when enabled, retrieval-profile v4,
using checkpoint format 2. Core v7 adds purge history and the separately scoped
purger; core v8 adds collector item-reuse grants only; core v9 adds the remote
attempt ledger; core v10 adds settlement columns and the accounting role;
core v11 adds private API cursor/profile/page/history state;
profile v4 adds explicit retrieval exclusions. Exact published legacy pairs
are admitted only when every recorded migration digest and expected column/table
set matches:

| Checkpoint core | Optional retrieval profile | Normalization into core 11/profile 4 |
| --- | --- | --- |
| 4 | 2 | Empty collection schedule, unknown historical HTTP status, empty ledger/exclusions |
| 5–6 | 2 | Empty ledger/exclusions |
| 7 | 3 | Empty ledger/exclusions |
| 8 | 3 or 4 | Empty ledger; empty exclusions only for profile 3 |
| 9 | 4 | Preserve attempts; add unset settlement columns and empty API progress |
| 10 | 4 | Preserve attempts/settlements; add empty API progress |

Core-only historical checkpoints may also adopt into a core-only target with
their exact published core history. These rules do not convert a core-only
checkpoint into a retrieval-profile checkpoint or admit arbitrary mixed histories.
Current checkpoints take the exact-history path without legacy normalization.
All restored collection schedules clear API continuation, profile hash, page count
and cursor history as well as HTTP validators, and sources remain disabled. A
restored cursor never silently resumes an external collection.
Restore does not provision the accounting login. It checks current independently
retained lifecycle policy before accepting historical content. A pre-purge
checkpoint containing records forbidden by that
policy fails with `RECOVERY_PURGED_CONTENT_PRESENT`; restoring hidden rows and
merely filtering them is not a substitute. Compatible post-purge state and exact
older supported histories follow the explicit adoption rules in the SQL purge
procedure. A rollback of both dataset and policy custody cannot establish that
the policy is current. No restore command authorizes reversal of a purge.
