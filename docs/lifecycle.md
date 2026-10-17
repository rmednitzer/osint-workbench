# Retention, preservation holds and logical retirement

This reference increment controls visibility and future processing. It does not
erase database rows, vectors, evidence objects, checkpoints, model memory or copies
already returned to a client. Physical reachability-based garbage collection,
backup expiry and erasure validation remain unimplemented. No legal compliance or
global-erasure claim follows from these controls.

## State and authority

The lifecycle identity is `(source_id, SHA256(external_id))`, shared by every
document version of that item. Default retention is the `manual` class with no
expiry. Class names are operator-defined labels, not built-in duration schedules;
an absolute timezone-aware `retain_until` controls expiry. No policy is inferred
from the original private setup, a model, or publication date.

Expiry hides all versions from serving and blocks new ingestion/enrichment for
that logical identity. An operator may extend retention again until the item is
permanently retired. Expiry is checked by database views at statement start; no
background sweeper is required to prevent new reads. Already admitted reads may
complete after the expiry boundary.

A preservation hold protects records without extending serving authorization.
Multiple holds can coexist and each has a unique, non-reusable ID. Explicit
retirement is refused while any hold is active. Releasing a hold never makes
expired content visible. Holds currently preserve data because no physical purge
exists; future GC must enforce them independently.

Retirement appends a permanent tombstone for the logical identity, cancels its
ready/running document jobs and revokes their fences in the same transaction.
There is no unretire or tombstone-delete command. Replaying or changing the source
under the same identity cannot make it visible again. Copies with a different
source/external identity are separate records and require separate dispositions.
This is not semantic duplicate detection or deletion of every syndicated copy.

Operators use a separate login inheriting `ow_lifecycle`, configured privately as
`OW_LIFECYCLE_DSN`. It has lifecycle and bounded job-control authority, not content
ingestion, model execution or public publishing authority. The ordinary writer
cannot change retention, holds, events or tombstones. No lifecycle tools are added
to MCP. Every change requires an operation ID, actor and rationale; exact retries
return the prior receipt and changed requests with the same ID fail.

Reader content grants now target security-barrier views. Raw document, snapshot,
chunk, assertion, briefing and optional member/vector reads are revoked. The
application also rejects reader identities accidentally granted raw content or
lifecycle access. Active documents, historical document/evidence reads, graph
assertions, cited products and hybrid/reranked candidates use the filtered path.
A product containing a suppressed selected document is withheld as a whole.
Aggregate status reports policy revision, expiry, retirement and hold counts, with
no actor/rationale or private policy keys.

Application database sessions take a shared lifecycle advisory lock in autocommit
**before** starting their data transaction. Lifecycle changes take the exclusive
lock. A waiting repeatable-read/serializable transaction therefore cannot inherit
a pre-retirement snapshot. Ingestion, index acceptance/activation, job completion
and cited-product creation either precede retirement or observe its effects.
Model dispatch also holds shared admission while checking the document and calling
the local runtime. Long collection/model work may delay retirement; lock acquisition
is bounded and reports `LIFECYCLE_BUSY`, never successful retirement.

This is a cooperative, database-scoped barrier for the current application, not
protection against a superuser, older binaries or arbitrary direct SQL writers.
Stop old processes during upgrade. It does not prove an already dispatched
computation stopped or recall text already disclosed. See PostgreSQL's
[advisory lock](https://www.postgresql.org/docs/18/explicit-locking.html) and
[view security](https://www.postgresql.org/docs/18/sql-createview.html) contracts.
Unrelated runtime work still proceeds concurrently under shared locks; lifecycle
changes serialize the reference dataset. Finer-grained admission remains a scaling
decision requiring equivalent race tests.
Application sessions also set UTC explicitly, so checkpoint and policy history
comparisons do not depend on different login roles' timezone defaults.
Equivalent row timestamp offsets compare as instants; original request/result
encoding remains unchanged for operation-hash verification.

Collection skips retired/expired items with a durable `suppressed_documents` count
and continues accepting other feed entries. Raw feed objects can contain several
items and remain in the private evidence archive. Retirement does not imply that
such shared bytes have been erased.

## Operator commands

Configure credentials outside the checkout. Replace the symbolic IDs and private
paths deliberately; these examples contain no operational configuration.

```sh
osint-workbench lifecycle inspect --document-id DOCUMENT_SHA256
osint-workbench lifecycle retention --document-id DOCUMENT_SHA256 --operation-id retention-1 --actor operator --rationale 'Selected retention policy' --retention-class short-lived --retain-until 2027-01-01T00:00:00Z
osint-workbench lifecycle hold --document-id DOCUMENT_SHA256 --operation-id hold-1 --actor operator --rationale 'Preserve for review' --hold-id review-1
osint-workbench lifecycle release --document-id DOCUMENT_SHA256 --operation-id release-1 --actor operator --rationale 'Review completed' --hold-id review-1
osint-workbench lifecycle retire --document-id DOCUMENT_SHA256 --operation-id retire-1 --actor operator --rationale 'Approved logical retirement'
osint-workbench lifecycle export-policy --file /private-storage/current.owpolicy
```

Retirement is permanent through the supported API; inspect holds and scope first.
To select indefinite retention, supply the class and omit `--retain-until`. A past
deadline hides the item immediately and cancels unfinished document work. A future
deadline hides it when reached; queued work then fails validation before model
dispatch. Cancellation revokes acceptance authority and does not prove physical
termination. Audit receipts preserve the original job fence.

Policy export is an explicit separate operation after changes. Keep its file and
receipt outside the database/evidence rollback set, on operator-managed encrypted
storage; keep the trusted hash, dataset ID and minimum accepted revision
independently. Export failure does not undo already committed lifecycle decisions.
Quiesce other policy writers when capturing the final policy for recovery, and
retain at least the last committed revision independently. An export describes its
snapshot; later decisions require a newer export and receipt.
Inspect the current revision and retry export using a new filename before relying
on recovery. `.owpolicy` files contain private identifiers and audit actors; the
Git ignore rule is a backstop, not a disclosure policy.

## Recovery policy and compatibility

Schema v4 and retrieval-profile v2 are additive migrations; published earlier
migration bytes remain unchanged. Provision the lifecycle login separately and
run `migrate-retrieval` when that optional profile is installed. Core-only migration
does not claim an old optional profile is upgraded. An unsafe reader configuration
fails closed until the profile's grant migration completes.

Checkpoint format 2 captures lifecycle state and its dataset UUID. Restore now
requires a separate current policy file, its trusted SHA-256 and an independently
retained minimum revision. It checks dataset identity, revision/history consistency,
preserved holds and monotonic tombstones before inserting anything. The policy's
operation history must reconstruct its retention/hold/tombstone state; missing
records, gaps, duplicate operations and inconsistent states are refused. Newer
policy keys are retained even when their documents were accepted after the older
checkpoint. Current policy is applied transactionally before any restored records
can be served. This does not make the restored dataset complete for later writes.

Offline restore cannot establish that a jointly rolled-back policy file, digest
and minimum-revision receipt are actually current. Independent receipt custody is
an explicit operational dependency, not a freshness guarantee supplied by a hash.

Format-1 checkpoints and schema-v3/profile-v1 pairs are explicitly rejected by the
new restore command. They remain readable with the previous tool revision in a
fresh isolated installation. Keep that binary/source and migration pair until
format-2 recovery is verified. Do not reconnect a legacy restore to consumers:
upgrading it alone invents a new dataset UUID and cannot establish the current
lifecycle policy of an existing dataset. Automated legacy adoption/reconciliation
is not implemented. If current format-2 recovery is unavailable, preserve the
legacy pair and resolve dataset/policy lineage explicitly before serving it.

See [the recovery procedure](recovery.md) and ADR-0021. Physical GC, restored
deletion of bytes, remote copies, context/cache profiles not yet implemented and
complete E39/E45/E48 acceptance remain outstanding.
