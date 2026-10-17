# ADR-0022: Review and journal bounded orphan-object deletion

Status: ACCEPTED for the bounded reference profile. Date: 2026-10-17.

## Decision and alternatives

Logical retirement deliberately retains all records and evidence. Failed ingestion
or restore can leave CAS files without metadata references. No change is safe but
leaves those orphans indefinitely. Deleting objects reachable only from visible
heads is rejected: it loses held, historical, retired and shared-feed evidence.
Purging a complete retired record graph is deferred until its FK, derived-product,
rollback, backup-expiry and preservation semantics have independent evidence.

Choose explicit operator-reviewed orphan plans and a durable filesystem intent
before deletion. There is no scheduler, MCP mutation or database migration. Reuse
the exclusive lifecycle barrier, exact compatible schema catalogue and complete
snapshot/collection-run reachability. Maintenance authority requires lifecycle
membership plus explicit reference/history reads and private filesystem access;
ordinary readers/writers receive no new grants. No external control plane or
provider is involved.

Plans bind dataset UUID, policy revision, reference-set hash, root device/inode,
file identities/content hashes, minimum age and operation label. Apply independently
revalidates them and refuses drift, unsupported row security and unexpected
inventory. The plan digest, rather than its label alone, is the replay identity.
A fresh journal requires every candidate to exist. Persisted matching intent
permits absent candidates on retry; existing files must still match. Directory
fsyncs precede a durable completion receipt. Failure leaves an explicit partial
outcome; it never claims database rollback restores deleted objects.

## Boundary, evidence and residuals

Inferred deployment assumption: current cooperative writers exclusively own the
selected CAS store and database. The operator must initially pair them correctly.
Privileged/raw writers, hostile concurrent filesystem mutation, whole-host rollback
and joint rollback/forgery of trusted receipts are not contained. Hashes provide
integrity comparison, not authentication. Single-host inode binding intentionally
prevents moving a reviewed plan to a new store; replan after migration.

Synthetic installed-build tests cover actual PostgreSQL reachability across retired
versions and held/shared records, stale reference/policy refusal, role denial,
changed/missing/symlink/hardlink/corrupt candidates, no deletion without intent,
post-unlink fsync failure, killed-process resume, row-security refusal, inventory
bounds and the real CLI. Revision-bound receipts identify which tests have passed;
this decision itself is not test evidence. Full record erasure, backup expiry and
operational recovery/custody remain separate unfinished workstreams.
