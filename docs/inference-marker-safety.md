# Host-local inference markers

The encoder, reranker and native generator share one operator-selected
`OW_INFERENCE_LOCK` on one host and OS account. The default remains
`/tmp/ow-inference-<uid>.lock`. This is cooperative admission, not isolation from
malicious code running as that account or an administrator. Separate lock paths,
users, hosts or mount namespaces do not coordinate inference.

## Filesystem custody

Use an absolute lock path without `..`. Its immediate parent must already exist,
be owned by the operator UID, give that UID directory read/write/execute access,
and deny group/other write. Modes `0700`, `0750` and `0755` are supported; `0700`
is preferred to keep filenames private. The existing default additionally permits
the literal root-owned, mode `1777` `/tmp` directory. Sticky-bit protection prevents
other UIDs from replacing entries owned by this operator; it does not prevent
other UIDs from precreating names. Unsafe precreated entries cause refusal.

Every ancestor must be owned by root or the operator and deny group/other write,
except root-owned sticky directories. Each component is opened as a directory
without following symlinks. An operator must also control mount configuration,
account membership, administrative access and filesystem durability. These checks
are Linux filesystem assumptions, not a portable network-filesystem guarantee.

The lock and receipt must be regular files owned by the operator, mode `0600`,
with exactly one hard link. No-follow, nonblocking opens reject symlinks and avoid
waiting on FIFOs/devices. Existing unsafe entries are never repaired or removed
automatically. Permission, custody and I/O errors return fixed error codes without
paths, file contents or native exception messages.

## Admission and uncertain outcomes

An open directory descriptor anchors lock and marker operations throughout the
admission. The held lock inode is exclusively flocked. A second process gets
`INFERENCE_BUSY`; any existing marker blocks normal admission with
`INFERENCE_OUTCOME_UNKNOWN`, including malformed or unsafe markers.

The persistent uncertain-work marker belongs to the externally managed local
generation daemon, not disposable encoder/reranker calls. Those children bind
their lifetime to the admission-holding parent with Linux parent-death SIGKILL and
refuse a missing or mismatched parent identity. That signal and lock release are
not atomic; short scheduling overlap remains possible. They do not create a
durable generation receipt or provide a cross-host resource scheduler.

Before completion dispatch, generation exclusively creates and fsyncs the marker,
then fsyncs its directory. The receipt contains only a random operation UUID,
generator identity digest, native peer PID and process-start token. Prompts,
responses, model paths, socket paths and credentials are excluded. Unavailable
peer identity refuses dispatch. Failure during receipt writing leaves any created
marker in place. Process termination releases the flock but leaves the receipt;
it does not establish that the native operation stopped.

Receipt reads are limited to 4096 bytes, including a post-stat growth check. Exact
field/type validation rejects malformed JSON, duplicate keys and invalid process
identities. Reads verify file metadata and the current directory entry against
the opened inode. Removing a receipt requires the same file identity, metadata
and bytes observed previously; unlink and directory fsync use the anchored
parent. Replaced or modified receipts remain fenced. Moved/replaced configured
parents or lock entries cause refusal rather than redirecting operations.

A complete, terminal native response authorizes removal before interpreting its
model content. A truncated or schema-invalid completed response is an application
failure, while an uncertain native response retains the marker. Explicit
reconciliation still requires the configured native identity/model, one idle
slot, matching generator receipt and the prior-process ownership checks. A
foreign PID with the saved start token remains alive; a different verified start
token establishes PID reuse. If its start token cannot be read, only an explicit
kernel no-such-process result establishes termination. A live PID, denied probe
or other liveness error returns `INFERENCE_PRIOR_PROCESS_UNKNOWN` and keeps the
reservation. The verified current native peer reporting idle remains supported.
Database job attempts, cancellation and result-acceptance fencing remain separate
requirements; clearing a marker grants no database mutation authority.

## Limits and recovery

Checking identity immediately before unlink is not an atomic defence against a
malicious same-UID peer renaming entries after the check. Such a peer can also
remove the lock or select another path. The same account must therefore contain
only trusted, cooperating processes, and the configured lock inode must remain
stable. Directory descriptors prevent pathname redirection; they do not turn this
protocol into a same-account security sandbox. Do not delete the lock as a reset.

If custody, identity or receipt validation fails, stop new inference work and
retain the receipt. Review the configured account, filesystem permissions and
native runtime under the operator's private recovery procedure. Old receipts
with missing/unavailable process-start identity are deliberately not silently
adopted. An idle slot on an unrelated runtime does not establish that prior work
stopped. Do not switch lock paths to bypass an uncertain reservation.

This filesystem protocol preserves the existing lock path and receipt field
names and adds no database migration. That statement does not waive migrations
required by other application features or make an older binary schema-compatible. Rollback requires stopping clients, establishing that
all native work has stopped, and resolving reservations under the current
procedure before replacing the binary. Keep the same lock path and safe custody;
restoring older code also restores its weaker filesystem checks. Never remove a
reservation merely to make an older binary start.

## Decision and verification boundary

Keeping pathname-only operations would preserve permissive configurations but
would allow FIFO hangs, symlink following and removal of substituted receipts.
Changing the default to a newly created private directory would require an
additional cross-process directory-adoption protocol and deployment migration.
The chosen bounded change retains the safe sticky-directory default, enforces
existing-directory custody, and anchors operations to descriptors. It provides
replacement detection under a cooperative account contract, with explicit
fail-closed behavior where identity cannot be established.

`tests/test_inference_marker.py` exercises real files and subprocesses: parent
permissions, component symlinks, FIFO/regular-file distinctions, hard links,
receipt bounds, replacement/mutation, parent/lock rename, fsync failure, process
exit, contention and native generation receipt ownership. Existing encoder and
native generation tests continue to cover ONNX execution, disconnect/crash,
uncertain-work refusal and explicit reconciliation. Exact passing evidence must
be bound to the tested revision; local environments that deny Unix sockets cannot
establish the native generation acceptance boundary.

## Local API receipt successor

[ADR-0052](adr/0052-local-inference-chat-api.md) preserves the native receipt shape
and adds a distinct `local-api-operation/1` shape with operation UUID, generator
identity and request hash. Both reserve the same stable lock. API receipts contain
no native peer PID/start claim. Neither adapter may reconcile another format.
The [API runbook](local-inference-api.md#ambiguous-outcome-and-explicit-resolution)
requires explicit operator termination confirmation and an evidence digest,
retaining a private exclusive resolution record before marker removal. A retry
accepts identical evidence only. An API health check cannot establish termination.
Resolution is operator attestation, not independent process/API proof. Resolution
files stay private and outside checkpoint/MCP/publication scope. Older clients
refuse this format; stop work and resolve with the current client before rollback.
