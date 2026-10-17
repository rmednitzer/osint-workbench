# Local workflow contract

The PostgreSQL database clock controls leases and retry eligibility. A claim increments
attempt and allocates a fresh fence. Completion, renewal and failure require the live
fence. Expired claims can be reclaimed; exhausted attempts become failed. Retry delay
is exponential, capped at 3600 s; the default maximum is five claims. Errors persist
bounded codes, never exception messages or source content. Job-key replay retains the
first accepted payload. Callers needing changed work must use a new versioned key.

Cancellation acquires the job row lock, sets a terminal state and revokes its fence.
It prevents later acceptance by the supplied worker. It does not prove process or
external execution stopped. A completion that wins the same lock before cancellation
remains succeeded. Failed/succeeded/cancelled jobs are not automatically restarted.
A new explicitly versioned operation is required. No remote side-effect worker exists.

`work-once` claims only `document.accepted`. It verifies raw/text objects and document
provenance, derives deterministic character chunks, then locks/rechecks the live job.
Chunks, `document.chunked` outbox work, success and the attempt event commit together.
A failed transaction accepts none of those effects. Unknown kinds remain queued.
The publisher does not claim exactly-once execution: retries can repeat computation.
Only database acceptance is fenced. Chunk identity includes split parameters.

Each collector holds a PostgreSQL session advisory lock for one source. Hash collisions
may serialize unrelated sources but cannot grant extra authority. All acceptance uses
that same connection. Lost connections stop acceptance and release the lock. Another
collector then marks previous running receipts interrupted. Each item and run count
commit together; a later failure preserves accepted evidence with a failed run receipt.
Replay deduplicates accepted versions. Last success advances only after all entries
are accepted. Disabled sources update status without acquisition. Parser-invalid items
fail the run rather than silently disappearing. HTTP fixtures replace acquisition only
in the isolated test harness; production cannot opt out of public-address validation.

The feed parser is a fresh isolated-mode Python process with no inherited credentials,
three CPU seconds, 512 MiB address space, 16 MiB result file and eight-second wall limit.
Resource limits are not a filesystem/network sandbox. Linux is the supported tested
platform. Parser results cross a strict typed JSON boundary. Normalized data remains
untrusted. A parser failure does not overwrite last success or erase partial evidence.

Migration v1 is immutable. The migration runner verifies every applied digest, refuses
unknown/gapped histories, applies v2 additively under one transaction/advisory lock,
and leaves existing data in place. Roll forward after application; do not run an older
worker against the newer schema or silently delete workflow history. Before a deployment,
back up database and objects together and validate restore in isolation. Complete backup,
restore, retention and operator recovery tooling remain unimplemented; this increment
establishes workflow crash/replay behavior, not a complete disaster-recovery claim.
