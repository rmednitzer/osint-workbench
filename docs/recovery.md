# Private checkpoint and isolated recovery

Format 2 is a bounded logical checkpoint of the workbench's `ow` application tables
and their referenced immutable evidence. It is **private data**, not a public
export. It contains source identifiers, document contents, job payloads, reviewer
identities/rationales and stored products. Do not commit, publish or send it to an
AI provider. `.owcp` files are ignored by Git as an additional backstop.

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
classified. A migration advisory lock excludes application migrations. Records
committed after the MVCC snapshot are excluded; this is not zero-data-loss backup
or WAL/PITR. A timestamp identifies capture transaction start, not completion or
the last accepted source event. See PostgreSQL's
[transaction isolation contract](https://www.postgresql.org/docs/18/transaction-iso.html).

All raw/text evidence referenced by snapshots and collection runs is read through
the integrity-checking store. Unreferenced files are excluded. Accepted ingestion
already makes objects durable before committing metadata, so the snapshot cannot
include a partially accepted document. Document bodies, chunk/vector coordinates,
assertion quotes and stored briefing hashes are checked. A concurrent deletion or
damaged object makes capture fail; no final file is published. Retention/GC must
coordinate with future checkpoints before either feature is enabled.

Limits are 100,000 rows across all application tables, 32 MiB row metadata, 64 MiB
referenced object bytes and 128 MiB total file. This in-memory reference profile
rejects larger datasets; it is not a streaming large-corpus backup. Output uses a
new 0600 file, fsync and no-overwrite promotion. Partial private staging files may
remain after process/host failure and require operator inspection.

Core storage, all document versions/heads, collection receipts, jobs/events,
chunks, enrichments, assertions/reviews and briefings are included. When installed,
the exact retrieval profile's spaces, generations, members, vectors and active
alias are included. Generated full-text vectors are rebuilt by PostgreSQL.

Credentials, database roles/grants, source URL catalogs, external routing policy,
inference ownership receipts, model/tokenizer binaries and host/deployment
configuration are outside the bundle. Protect and recover them separately. A
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
generations are preserved. These changes are intentional recovery dispositions,
not byte-for-byte resurrection of a running process.

Before connecting consumers, check representative old/current document IDs,
evidence hashes, review states, cited products and search through the actual reader
and MCP client. Inspect stale products and degraded retrieval explicitly. Restore
the correct private model configuration and verify its identities before hybrid
reads. Reconcile ownership of any computation still running on an old host; a
restored job cannot prove that computation has stopped. Reconcile external
effects and additional deployment-specific policy before enabling sources or
submitting explicit new operations. Keep external supervisors stopped: an explicit
`collect` with an enabled private configuration updates the source row and can
re-enable collection. Disabled restored rows are not a fleet-wide interlock.
This increment has no overall deployment readiness gate or physical GC,
cross-host reconciliation or general operator command to resume quarantined work.

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
