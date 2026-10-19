# Local workflow contract

The PostgreSQL database clock controls leases and retry eligibility. A claim increments
attempt and allocates a fresh fence. Completion, renewal and failure require the live
fence. Expired claims can be reclaimed; exhausted attempts become failed. An explicit
retryable failure schedules `min(3600, 2 ** min(attempt, 12))` seconds from the database
clock; an expired lease is eligible for immediate reclaim. The default maximum is
five claims. Errors persist bounded codes, never exception messages or source
content. Job-key replay retains the
first accepted payload. Callers needing changed work must use a new versioned key.

Cancellation acquires the job row lock, sets a terminal state and revokes its fence.
It prevents later acceptance by the supplied worker. It does not prove process or
external execution stopped. A completion that wins the same lock before cancellation
remains succeeded. Failed/succeeded/cancelled jobs are not automatically restarted.
A new explicitly versioned operation is required. Explicitly routed enrichment can
call the governed compatible cloud adapter. Its reservation, dispatch, unknown
outcome and separate accounting-settlement rules are described in
[cloud routes](cloud-routes.md); job fencing cannot undo a provider request or charge.

`work-once` claims only `document.accepted`. It verifies raw/text objects and document
provenance, derives deterministic character chunks, then locks/rechecks the live job.
Chunks, `document.chunked` outbox work, success and the attempt event commit together.
A failed transaction accepts none of those effects. Unknown kinds remain queued.
The worker does not claim exactly-once execution: retries can repeat computation.
Only database acceptance is fenced. Chunk identity includes split parameters.
`enrich work-once` is a separate explicit worker for its configured generator;
the core worker does not claim enrichment or arbitrary queued job kinds.

`work --max-jobs` repeats that same claim/acceptance path for one bounded tick
and emits aggregate counts; `work-once` retains its per-job output. Both open
the evidence store read-only. The [operational profile](operational-profile.md)
defines cap/idle/failure semantics, supervision and the unsupported downstream
backlog; the [deployment procedure](deployment.md) covers explicit shared read
custody. Neither command initiates model downloads, inference or cloud work.

## Explicit chunk recovery and receipts

After inspecting the original job and correcting its cause, a writer can request
chunking of a retained visible document with an intentional operation ID:

```sh
osint-workbench chunk enqueue --document-id <document-digest> --operation-id repair-1
```

Use `job inspect <job-id>` to inspect the returned job, then run the
normal chunk worker. Reusing `repair-1` for that document/algorithm preserves the
same job even when failed, cancelled or succeeded. A different ID creates a new
operation with its own retry budget; it never resets the original. Neither enqueue
nor chunking runs enrichment, inference, cloud work or downstream consumers.
Historical versions can be chunked without changing the current source head.
Retired/expired documents remain refused. IDs are bounded nonsecret labels;
see [ADR-0054](adr/0054-explicit-chunk-operations.md) for algorithm binding and rollback.

The enqueue result contains `job_id`, `job_status`, `enqueue_effect` and
`requeued: false`. `pending_or_running` describes current stored nonterminal
state; it does not assert that this call inserted a new row. `terminal_preserved`
means the same terminal job is retained and no new work was scheduled.
`work-once` success adds `downstream_enqueue`; the same receipt is stored in the
job result. A terminal downstream receipt does not turn chunk success into
end-to-end pipeline completion. `document.chunked` has no generic consumer.
Receipts describe committed transaction-time observations; a later worker may
change nonterminal status.

`import-text` retains `document_id` and adds `document_effect` (`inserted` or
`version_replayed`) and a `processing` receipt. A newly inserted job reports
`inserted`/`ready`. A preserved conflicting job reports `existing_preserved` with
unknown ID/status. Immutable replay reports `not_enqueued`, also with unknown
ID/status; it does not inspect or repair earlier jobs. The Python ingestion API
keeps its default document-ID return; `describe=True` opts into this envelope.
Internal current-item reconciliation can report `current_item_reused` without
an enqueue. Collectors need no downstream read/update grants, and their aggregate
accepted-document counts are not processing-success counts.

Each collector holds a PostgreSQL session advisory lock for one source. Hash collisions
may serialize unrelated sources but cannot grant extra authority. All acceptance uses
that same connection. Lost connections stop acceptance and release the lock. Another
collector then marks previous running receipts interrupted. Each item and run count
commit together; a later failure preserves accepted evidence with a failed run receipt.
Replay deduplicates accepted versions. Last success advances only after all entries
are accepted. Disabled sources update status without acquisition. Parser-invalid items
fail the run rather than silently disappearing. Native HTTP/TLS fixtures route
synthetic peers through the actual transport and parser; production has no switch
to opt out of public-address validation. Item reuse and source-head reconciliation
follow [the scheduled acquisition contract](scheduled-acquisition.md).

The feed parser is a fresh isolated-mode Python process with no inherited credentials,
three CPU seconds, 512 MiB address space, 16 MiB result file and eight-second wall limit.
Resource limits are not a filesystem/network sandbox. Linux is the supported tested
platform. Parser results cross a strict typed JSON boundary. Normalized data remains
untrusted. A parser failure does not overwrite last success or erase partial evidence.

Published migrations are immutable. The runner verifies applied digests, refuses
unknown/gapped histories and applies additive versions under its transaction and
advisory lock. The current supported pair is core v12/retrieval v5. Roll forward;
do not run an older worker against newer state or silently delete workflow history.
Before deployment, preserve the database/object pair and verify isolated restore.
Bounded [recovery](recovery.md), [lifecycle](lifecycle.md), [GC](garbage-collection.md)
and [SQL purge](retired-record-purge.md) are implemented with separate contracts.
Full-host/PITR recovery, all-copy erasure and complete operational acceptance remain
open; workflow crash/replay tests alone do not establish disaster recovery.
