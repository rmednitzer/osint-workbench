# ADR-0059: Verify retained chunk output before completion

Status: ACCEPTED for the bounded character worker. Date: 2026-10-20.
Verification belongs to the exact candidate's installed/native checks.

## Context and drivers

The worker derives deterministic chunks from verified document evidence. Its
previous `ON CONFLICT DO NOTHING` inserts only proved that a uniqueness key was
occupied. A differently shaped row with the same ordinal, an incompatible chunk
identity, or extra retained ordinals could survive while the worker reported
success and scheduled downstream work. Existing writer INSERT authority permits
such rows; this is a producer/history consistency defect, not privilege escalation.
Recovery checks some body/coordinate/hash relationships, but recovery validation
cannot substitute for normal worker acceptance.

Completion must describe the output actually retained, preserve immutable evidence,
remain bounded, and keep chunk rows, downstream enqueue and the success event in
one fenced transaction. Compatible historical rows and concurrent compliant
operations must remain reusable.

## Alternatives

- No change: keeps fast deduplication but can certify incompatible retained output.
- Overwrite conflicting rows: hides producer/history faults and violates immutable
  evidence semantics; rejected.
- Check only inserted row counts or individual conflicting rows: cannot detect
  extra retained ordinals; rejected.
- **Selected:** compare the complete bounded document/algorithm row set with the
  deterministic expected output before enqueue and completion.

## Decision

After idempotent inserts, compare retained chunk IDs, document/algorithm identity,
ordinals, original-text coordinates, text hashes and bodies with the expected
rows. Read at most the expected count plus one row, using the existing ordinal
index. Perform comparison in SQL and return only the match result, so corrupt
retained bodies are not copied into an unbounded Python result.

The downstream `document.chunked` identity must also retain the exact expected
payload, including integer chunk count. Generic enqueue still preserves the first
payload; this producer checks it under the acquired job-row lock before accepting
success. A conflicting prior payload is neither rewritten nor reset.

A chunk-set mismatch raises `CHUNK_INTEGRITY_MISMATCH`; a conflicting downstream
payload raises `CHUNK_DOWNSTREAM_MISMATCH`. The transaction rolls back newly
inserted chunks and accepts neither downstream enqueue nor success. The separate
failure transition preserves the attempt with a fixed terminal diagnostic; a stale
lease remains superseded. Existing conflicting rows and prior downstream jobs are
not repaired, removed or relabelled. A new operation ID cannot resolve an integrity
conflict merely by retrying it.

Concurrent compliant workers derive identical immutable rows. Uniqueness-conflict
waiting and subsequent validation under the default Read Committed transaction
allow reuse of committed identical output. The final job fence and lifecycle
checks remain mandatory. Validation describes the set at its SQL statement; it
is not protection against an independently authorized writer inserting different
rows later, a superuser, or old workers. No new writer authority is granted.

## Consequences, blast radius and rollback

Only character-chunk acceptance changes. No dependency, schema, grant, MCP tool,
chunker identity or inference policy changes. Correct partial sets can be completed;
other document/algorithm sets remain outside this comparison. Historical success
receipts are not retroactively qualified. Conflicts require operator investigation
and a separately reviewed recovery decision, not an automatic overwrite command.

Quiesce workers before reverting the binary through a protected PR. No migration
or data rewrite needs reversal, but the old binary again permits false completion
on conflicting output. Preserve failed attempts and the database/evidence pair.

## Verification

Native SQL regressions must distinguish incompatible retained identities, text,
coordinates and extra rows from valid replay and partial completion. They must
verify conflict preservation, mismatched downstream payloads including Boolean
counts, rollback of new rows, no new downstream job, fixed
terminal failure and concurrent compatible operations. Existing late-fence and
pre-commit refusal cases remain required. Both supported LTS installed profiles
are acceptance gates; missing local PostgreSQL is unavailable evidence.
