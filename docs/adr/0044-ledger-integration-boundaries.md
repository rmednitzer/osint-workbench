# ADR-0044: Preserve ledger inventory and fresh admission snapshots

Status: Accepted

## Context and decision criteria

The remote reservation and settlement increments added `remote_operations` to
checkpoint and purge inventories. Purge's primary-key map omitted that table,
so the first ledger row, including a denial, made plan/apply raise `KeyError`.
Accounting is retained evidence and must remain unchanged during content purge.

Reservation admission takes a route/currency advisory transaction lock before
reading exposure and unresolved operations. Under a Repeatable Read session
default, the blocking lock statement establishes a snapshot before waiting.
The next lock holder can therefore miss its predecessor's committed attempt.
The required invariant is one admission at a time with fresh committed exposure
and replay state, independent of the session's default isolation.

The PR #9 merge incident separately showed that branch metadata checks do not
preflight a later server-generated merge message. Existing history remains
public; this decision does not authorize rewriting it.

## Alternatives

| Option | Consequences |
| --- | --- |
| No change | Populated-ledger purge stays unavailable; Repeatable Read admits stale reservations |
| Require operators to configure Read Committed | Fix depends on undocumented external state and can regress with role/database changes |
| Acquire a session lock before beginning a transaction | Fresh snapshots are possible, but require additional session-lock ownership and cleanup paths |
| Explicit Read Committed reservation transaction | Keeps transaction-lock cleanup and existing authority; subsequent reads refresh after the lock wait |
| Omit ledger rows from purge inventory | Avoids the crash but hides retained accounting changes from plan freshness |
| Add ledger to purge deletion closure | Destroys retained accounting and contradicts the accounting contract |

## Decision

Add the ledger's `attempt_id` to purge's fixed primary-key map. Keep the table
outside the deletion closure. Plan freshness still includes every ledger row.

Set Read Committed as the first statement on the fresh reservation transaction,
before any snapshot-establishing query. Keep the route/currency advisory lock,
unresolved-attempt guard and exposure check in the same transaction. Do not
change global, database or role defaults, settlement isolation or grants.

Add an optional bounded planned-message preflight to the existing publication
scanner. Use the same URL, credential, private-value and metadata-email policy,
without base-email inheritance for planned messages. Reject special files,
symlinks, oversized input, NUL and invalid UTF-8 with redacted diagnostics.
Require agents to review explicit merge text instead of implicitly copying a PR
description. This remains an operator preflight, not automatic GitHub interception.

## Verification and assurance allocation

- Native populated-ledger purge covers denied, reserved, dispatched, unknown and
  settled rows. Planning, application and replay must preserve complete ledger
  values and exposure while deleting the selected content.
- Two native concurrency cases configure and verify actual session defaults as
  Repeatable Read. A separate lock holder waits until both reservations are
  blocked on the real advisory lock; after release only one may be admitted,
  for both a shared cap and a shared unresolved operation.
- Native Git history and planned-message tests distinguish a clean PR head
  from a merge message containing a synthetic session link. Input guards and
  private-value cases must fail without printing paths or matched values.

These refine existing STPA C97/C98 and the purge/publication boundaries, with
C101/C102 in [the STPA register](../assurance/stpa.md). Passing authored fixtures
does not establish live-provider accounting, physical erasure or anonymity.
Actual native outcomes belong to the tested candidate's CI, not this decision.

## Impact, reversibility and rollback

No migration, dependency, API, grant or global database setting changes. Core 10,
retrieval 4 and checkpoint format 2 remain unchanged. Blast radius is reservation
admission, purge inventory ordering and optional publication preflight.
Rolling back the code restores the defects without transforming stored rows;
an already applied content purge remains irreversible. Avoid running the older
purger against populated ledgers. Keep affected remote dispatch paused if the
reservation fix must be reverted. The preflight can be removed independently,
but the existing metadata gate must remain. Historical publication findings
stay recorded and are not cleared by a green new-commit range.
