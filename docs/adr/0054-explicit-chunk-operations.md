# ADR-0054: Explicit chunk operations and enqueue dispositions

Status: ACCEPTED for the bounded chunk/ingestion profile. Date: 2026-10-19.
Verification belongs to the exact candidate's installed-artifact checks.

## Context and criteria

Ingestion deduplicates immutable versions and preserves terminal jobs. Re-importing
an accepted document therefore cannot recover failed chunking. Silent replay and
an unsupported downstream outbox can be mistaken for completed processing.
Recovery must preserve attempts, evidence, source heads, lifecycle admission and
least-privilege collector grants. It must not replay uncertain inference work.

## Alternatives

- No change: preserves safety but leaves no supported explicit chunk recovery.
- Reset a failed/cancelled job on import: hides operator intent, destroys terminal
  semantics and encourages unsafe inference/provider retries.
- Teach every collector to inspect/update jobs: widens producer authority and
  couples acquisition to downstream processing.
- **Selected:** a writer-only operation command with a stable versioned identity,
  additive ingestion receipts and transactional downstream dispositions.

## Decision

`chunk enqueue --document-id <digest> --operation-id <identifier>` binds the
immutable document, its actual snapshot, the supplied operation ID and exact
character chunker version. Its namespaced digest cannot collide with ingestion's
original document-key job. Repeating a request preserves its first job, including
terminal status; a deliberately different operation ID creates independent work.
The ID is scoped by document/snapshot/algorithm, not a global audit principal.
No algorithm selector, automatic retry/reset or new worker kind is introduced.

Retained visible historical versions may be processed without changing their
current source head. Lifecycle suppression denies new operations; the worker
still verifies raw/text provenance and rechecks lifecycle/fence on acceptance.
Original two-field ingestion payloads remain supported. Explicit payloads require
both operation ID and the supported algorithm version; future versions are refused.

`import-text` adds document and processing dispositions. Python ingestion retains
its default string return and offers `describe=True`. New insert receipts use the
INSERT row count, not a job SELECT or UPDATE. Replays perform no enqueue and report
unknown job ID/status, not fabricated readiness. Collection aggregate counts remain
acquisition receipts and do not establish downstream completion.

The worker reports and persists the atomic downstream job status using the same
transaction as chunk insertion, its final lease guard and success event. A terminal
`document.chunked` job stays terminal; chunk success does not restart it or prove
that any downstream consumer ran. Generic enqueue receipts describe pending/running
or preserved terminal work without claiming to distinguish insertion from conflict.
All statuses are transaction-time observations, not promises of future execution.

## Consequences, blast radius and rollback

No schema, grant, dependency or MCP change. Explicit recovery requires writer
credentials, which already hold job authority. Collectors retain INSERT-only job
permissions. Operator IDs are nonsecret bounded labels; do not put private content
in them. New operations may repeat local character computation; identical chunks
and the downstream identity remain deduplicated. This is not an exactly-once claim.

A fresh operation never clears local/API admission markers, dispatches a model,
settles a cloud reservation or resets another job. Broader workflow scheduling,
backfill and operator-authenticated audit services remain open. No useful-model
qualification or full roadmap acceptance follows from this change.

Quiesce workers before binary rollback. There is no reverse migration. Older workers
reject explicit four-field payloads, so keep the upgraded binary until those jobs
are completed/cancelled, or restore a matching pre-change database/evidence pair.
Existing ingestion payloads and default Python string returns remain compatible;
CLI consumers must tolerate the documented additive receipt fields.

## Verification

Installed tests exercise explicit intent at the CLI, concurrent same-operation
deduplication, independent operation IDs, original terminal preservation,
transactional downstream terminal feedback, original payloads, version-pair
refusal, final-lease and pre-commit rollback, historical-head preservation,
retirement refusal and collector receipts under unchanged actual SQL grants.
Both required native LTS profiles remain necessary for acceptance; local tests
without PostgreSQL do not establish these database behaviors.
