# ADR-0033: Retain filesystem admission through evidence-reference commits

Status: ACCEPTED for implementation; revision-bound execution evidence pending.
Owner: maintainer. Date: 2026-10-17.

## Context and counterexample

Orphan GC checks all retained references under the exclusive database lifecycle
session lock, then deletes selected CAS objects. That lock ends when its database
backend dies, even if the GC process remains alive and has not observed the
disconnect. A cooperative writer can then reuse an existing object and commit a
new reference before GC unlinks it. The earlier reference snapshot was accurate
but no longer excludes subsequent acceptance. Checking session health immediately
before unlink still leaves a check/action interval; a live Python connection
object is not evidence that the backend's lock remains owned.

SC4, C21 and C31/C32 require a deletion/acceptance boundary that survives this
database-session loss. Preserve the existing reference checks, durable intent,
anchored file identity and age rules. This decision contributes to orphan-GC
integrity; it does not establish complete erasure, storage durability on every
filesystem or a new general distributed-lock service.

## Alternatives and decision

| Alternative | Benefit | Cost and boundary |
| --- | --- | --- |
| No change | No additional locking or producer changes | The backend-loss/reference-reuse counterexample remains |
| Suspend GC | Immediately removes this deletion race | Reclaims no orphan bytes; a valid degraded disposition until the protocol is verified |
| SQL heartbeat before each unlink | Detects many lost sessions | Cannot make SQL health observation atomic with filesystem deletion |
| Durable deletion claims | Could coordinate recovery through explicit persistent state | Requires claim expiry/reconciliation and every producer's acceptance protocol; a claim alone does not prevent late object reuse |
| Store-root shared/exclusive filesystem admission | Independent process-owned exclusion survives database backend loss | Every evidence producer must participate through metadata commit; local inode/locking semantics and upgrade coordination become explicit assumptions |

Choose the filesystem barrier for the supported local-Linux reference profile.
Use `flock` on the no-follow opened root directory inode, rather than creating a
replaceable lockfile or introducing an entry the GC inventory must ignore.
The lock remains advisory. Unsupported locking/runtime/filesystem errors fail
closed; no unlocked compatibility fallback is allowed. Lock waits are bounded
and produce explicit failure rather than successful deletion or acceptance.

## Protocol and allocation

The order is **database lifecycle admission, then store filesystem admission,
then reference/acceptance state**. Never acquire filesystem admission and then
wait for a new database lifecycle admission. GC takes exclusive admission in both
domains and establishes its final SQL reference snapshot only after owning the
filesystem lock. Otherwise backend loss while waiting for that lock could permit
a writer's intervening commit and leave GC using stale references.

Evidence producers take shared filesystem admission before writing or reusing
objects and retain it until their database transaction has actually committed or
rolled back and closed. `store.transaction` owns this ordering: enter fresh
database admission, acquire the anchored root lock, exit the inner connection
context before releasing filesystem admission. A surrounding connection context
that commits only after the filesystem context exits is insufficient.

Allocate this protocol to `Database.ingest`, the complete collector acceptance
scope and isolated restore. Collection includes raw feed publication, text puts,
per-item commits and final run/cache-pointer commits. A 304 can reuse a cached raw
object without any new `put`, so put-only locking does not cover that path.
Restore holds admission from its new root's first publication through metadata
commit. The internal `ingest_stored` primitive remains subject to the enclosing
acceptance protocol; accepting hashes without that ownership is not a supported
producer path.

Standalone `EvidenceStore.put` takes shared admission through object publication
and fsync. This protects publication itself; a later database acceptance needs
the enclosing transaction protocol, not a remembered successful standalone put.
Internal nested operations may reuse an actively owned admission on the same
store instance to avoid self-deadlock. Ownership must not leak between independent
threads/transactions or survive the context that owns the descriptor. Read-only
inspection inside exclusive GC must not attempt an incompatible second lock.

Use the pinned root descriptor for object/shard operations, or reject a different
root identity before using a reopened path. Retain no-follow and digest checks.
The path string alone is not the lock identity. Do not silently unlock another
operation's descriptor; close admission deterministically on errors, commit
failure and process completion. Backend death does not close this process's root
descriptor. If GC keeps it while its backend disappears, writers may obtain
database admission but cannot publish/reuse evidence and commit references until
GC finishes filesystem deletion and releases its lock.

## Compatibility, limitations and rollback

One authoritative database dataset must correspond to a store root. Serializing
another database's writer cannot reveal that database's already committed
references to GC. Aliased paths are safe only when they reach the same admitted
directory inode; copied roots, inode replacement and shared remote storage need
their own acceptance evidence and binding. Parent directories and permissions
remain trusted against hostile replacement. No broad permission changes are
introduced to make a different UID's access succeed.

Local Linux directory-flock behaviour is the reference boundary. Network
filesystems, cross-host lock managers, Windows/macOS, containers with independent
mounts and storage failure semantics are not inferred from a local passing test.
File descriptors and lock ownership across fork/exec also require care; inherited
ownership can delay release. This is not hostile-kernel or privileged-process
containment.
The Linux [flock contract](https://man7.org/linux/man-pages/man2/flock.2.html)
describes advisory open-file-description ownership and filesystem-dependent
semantics; the [open contract](https://man7.org/linux/man-pages/man2/open.2.html)
describes descriptor/path anchoring. These contracts motivate the design; they
are not execution evidence for a particular deployment.

Older binaries, direct SQL reference writers and independent filesystem mutators
can ignore advisory admission. Stop and replace old producers before enabling GC
under this protocol. A new marker or Python API cannot retroactively force them
to participate. New code must reject unsupported admission, while operational
exclusion of nonparticipants remains a deployment obligation. Rolling back to
older writer or GC code requires disabling GC and quiescing participants; do not
mix protocols and assume the database lock alone is sufficient.

No checkpoint/policy layout or migration change is required for this lock
protocol. Existing objects and plans still require their ordinary integrity,
reference and identity checks under the new admission. Suspending GC leaves
possible orphan bytes retained; it does not authorize removal of referenced data.

## Required verification

Require native process and PostgreSQL cases that terminate the actual GC backend
after reference validation, attempt an actual writer's reuse/commit, and observe
blocking or explicit bounded refusal until filesystem release. Also exercise
backend loss before final validation, standalone put, cached 304 acceptance,
multi-commit collection, restore, nested ownership, separate process/store
instances, timeouts and error cleanup. Verify no accepted metadata references a
deleted object and verify the lock lifetime through real commit. Distinguish
injected exceptions from actual backend/process termination. Until a
revision-bound receipt records execution, these are obligations and a proposed
remediation, not a verified closure claim.
