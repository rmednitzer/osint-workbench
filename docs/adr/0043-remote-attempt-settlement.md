# ADR-0043: Settle remote attempts by evidence-bound operator assertion

Status: ACCEPTED for the bounded settlement slice. Date: 2026-10-18.
Extends [ADR-0042](0042-governed-compatible-cloud-route.md). Invoice import,
automatic provider usage reconciliation and batch reconciliation remain open
under [ADR-0013](0013-accounting-batch.md).

## Context and decision drivers

ADR-0042 counts every attempt that may have reached the provider at its
worst-case reservation unless the response reported plausible usage, and it
refuses another attempt for the same job while one is unresolved. That is
correct at dispatch time, but nothing could resolve it afterwards. One dropped
connection permanently consumed part of a route's cap, and a worker that died
between reserving and sending left a reservation that could never be cleared.
Resolving that needs provider-side evidence, which this software cannot fetch
or verify, and it must not let the spending identity lower its own exposure.

The drivers are:

- no silent zero for unknown cost;
- separation between the identity that spends and the one that settles;
- a settlement must not race a still-running worker;
- exact Decimal amounts and append-only history that survive checkpoint and
  restore;
- no provider calls, invoice parsing or private evidence in the database.

## Alternatives, including no change

- **No change.** Operators edit rows with ad hoc SQL. That has no authority
  boundary, no evidence binding, no protection against a live worker and no
  receipt.
- **Automatic reconciliation from provider usage APIs.** This needs vendor
  adapters and live calls, each of which is a disclosure and spending decision.
  It is out of scope for a contract slice.
- **A separate append-only settlements table.** It is clean as a record. But a
  late worker's outcome and the settlement would then touch different rows, so
  ordering them would depend on advisory locks and on each session's isolation
  level.
- **Settlement columns on the attempt row, written by a separate accounting
  role and guarded by the existing state-machine trigger.** Chosen. The row
  lock serializes settlement against any worker update. A settled row is then
  refused by the trigger under read committed, and by serialization failure
  under repeatable read.

## Decision and authority boundary

Core migration 10 adds settlement basis, settled amount, evidence digest,
actor, rationale and a database-assigned time to `ow.remote_operations`. It
also adds a `NOLOGIN` group, `ow_accounting`.

- `ow_accounting` may read the ledger and update only the five operator
  settlement columns.
- The writer's insert grant narrows to the attempt columns. It can no longer
  insert a pre-settled or back-dated row.
- The command refuses any login that is also a writer member. Reader
  validation refuses accounting membership.

`osint-workbench cloud-ledger unsettled` lists attempts that still hold an
estimate. `osint-workbench cloud-ledger settle` records one settlement per
attempt, with these rules:

- **Bases.** `invoice`, `usage_export` and `provider_statement` require an
  evidence file. The file is read without following symlinks, bounded at
  64 MiB, and stored only as its SHA-256. `not_dispatched` is accepted only
  for a row still `reserved`, only at zero and without evidence. A reserved
  row is provably unsent, because the dispatched transition commits before
  any request.
- **Currency.** It must equal the attempt's currency. Amounts may exceed the
  reservation: an invoice is not bounded by the declared-price estimate.
- **Scope.** Denied and released attempts need no settlement and are refused.
- **Live attempts.** Reserved or dispatched rows younger than ten minutes are
  refused, both in code and by the trigger. The worker's request deadline (at
  most 120 seconds) now starts before the dispatched row commits, and an
  expired deadline releases the attempt before any connection. A stalled
  worker therefore never sends after the window opens, except across host
  suspend, which is outside the monotonic clock.
- **Finality.** A settled row is immutable to every role. An identical retry
  returns the receipt; a changed request fails with `SETTLEMENT_CONFLICT`.

Exposure uses the settled amount when present. A settled attempt no longer
blocks another attempt for the same operation, because its outcome is no
longer unknown.

Recovery adopts exact core-9 checkpoints with every attempt unsettled, and
refuses partial settlement columns. Purge reads the new columns and still
never modifies the ledger.

## Consequences, blast radius and reversibility

- Operators can recover cap capacity after unknown or failed attempts, but
  only by asserting a provider-evidenced amount under a separate login.
- A wrong settlement cannot be edited in place. Correcting it requires a
  reviewed database change outside this tool, which is deliberately visible.
- The software does not verify that the evidence file says what the operator
  asserts. It binds the assertion to the file's digest, actor and rationale.
- Rationale text is retained with the ledger and included in checkpoints.

Reverting the code removes the command. Migration 10 is additive: unsettled
rows behave exactly as under core 9, and settled rows remain retained history.
An older binary refuses core 10.

## Discriminating verification

Real PostgreSQL tests cover:

- settlement of an unknown outcome, followed by a successful new attempt for
  the same operation;
- idempotent retry and conflicting changes;
- settlement above the reservation exhausting the cap;
- currency, basis, scope and unknown-attempt refusals;
- live-row refusal by the code and, separately, by the database;
- zero settlement of a stale reservation, after which dispatch is refused;
- a settlement holding the row lock while a late worker outcome waits, under
  read committed and under repeatable read;
- writer, reader, collector and lifecycle refusal, and a writer-and-accounting
  login refused;
- the writer unable to insert settlement or timestamp columns, and accounting
  unable to change outcomes, reservations or settlement time, or delete rows;
- immutability of settled rows;
- bounded listing;
- a CLI run with a hashed evidence file;
- exact checkpoint/restore of a settled row at the largest storable amount;
- core-9 adoption, and refusal of partial columns;
- a stalled worker releasing the attempt instead of sending.

Removing the settled-cost exposure term, the settled exception in the replay
guard, the writer-membership refusal, the in-flight check, the deadline
anchoring, or either trigger guard each makes a test fail. This is contract
evidence, not invoice, provider or legal evidence.
