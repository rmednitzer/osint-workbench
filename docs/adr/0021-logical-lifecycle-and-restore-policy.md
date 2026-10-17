# ADR-0021: Enforce logical lifecycle at reads and reconcile policy before restore

Status: ACCEPTED for the bounded reference profile. Date: 2026-10-17.

## Context and decision drivers

An old checkpoint can revive content retired after capture. Filtering only MCP
leaves raw reader SQL and derivative paths exposed. Holds and expiry also have
different goals: preserve evidence versus authorize serving. Required properties
are explicit authority, permanent logical retirement, no stale-worker acceptance,
auditable operation identity and recovery without silently rolling policy back.

## Alternatives, including no change

1. No change: retain the tested recovery baseline and do not claim retention or
   restored deletion enforcement. This is preferable to unverified erasure scripts.
2. Application predicates alone: small change, but easy to bypass through direct
   reader SQL, product projections or a forgotten inference path.
3. RLS plus privileged trigger/functions and per-record locks: potentially more
   granular, but introduces owner/bypass semantics and privileged code, with more
   migration and concurrency cases than this reference increment needs.
4. Filtered security-barrier views, scoped grants, a cooperative lifecycle barrier
   and independently retained policy snapshots. Choose this for the bounded
   single-operator reference; serialization cost is preferable to hidden races.

## Decision and authority

Core migration v4 adds dataset/revision identity, operator-controlled retention,
holds, permanent logical-key tombstones and operation events. Reader raw-content
grants are replaced by filtered views; normal writers cannot modify policy.
Application sessions obtain shared admission before any transaction snapshot;
lifecycle mutations obtain exclusive admission. Fixed operators and typed CLI
commands perform these writes; MCP remains seven read-only tools.

Expiry filters all versions without waiting for a worker. Holds preserve data and
block explicit retirement while leaving expiry effective. Tombstones cancel
pending/running document work and prevent re-ingestion under the same logical key.
Late results cannot regain a cancelled fence. Existing derived bytes are retained
privately and excluded from reader/active processing paths; physical GC is separate.

Format-2 restore requires a separately trusted policy hash and minimum revision,
checks dataset/history/state/hold/tombstone consistency and applies current policy
before committing restored metadata. An offline tool cannot detect simultaneous
rollback of every trusted receipt; independent custody remains necessary.

## Consequences, reversibility and blast radius

Only the extracted application and disposable CI are changed. Old migration bytes
are immutable; the new optional profile migration is versioned separately. Stop
old binaries and upgrade core and installed optional profiles before serving.
Legacy format-1 recovery requires its previous tool/schema pair in isolation;
automated adoption into an existing lifecycle dataset is not implemented. This
format and grant compatibility break is explicit, not a silently accepted restore.

Retention extensions and hold releases are explicit audited actions. Tombstones
have no supported reversal. Physical bytes, shared feeds, backups and previously
disclosed copies are not erased. A rollback must not drop current tombstones or
holds; preserve independently retained policy and prefer a forward repair. Do not
run the old reader against upgraded grants or restore an old pair directly into
service. Keep the prior isolated recovery route until the new pair is tested.

## Evidence and residuals

R05/R14/R20/R27/R29/R33/R34/R49/R50/R54; E08/E13/E26/E39/E45/E48 subsets. Native
tests cover holds/expiry, all document versions, reader grant/predicate bypass,
jobs/fences, collection suppression, PostgreSQL/pgvector/rerank, real MCP, stale
snapshots and older-checkpoint/newer-policy recovery. Revision-bound CI determines
verified status. No physical-erasure, complete lifecycle, semantic-quality, arbitrary
writer/superuser containment, remote client recall or full E48 claim is made.
