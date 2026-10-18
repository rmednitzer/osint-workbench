# ADR-0002: Use PostgreSQL as record, graph, job and accounting authority

Status: PROPOSED, revision 2. Owner: maintainer. Date: 2026-10-17.

## Context
Retaining parallel database semantics and separate state files makes transaction and recovery boundaries harder to reason about.

## Alternatives and no change
Keep the prototype stores; use SQLite/graph/vector/queue services separately; or use PostgreSQL with optional pgvector plus immutable files. No change means keep the prototype private; prefer that over unsafe publication.

## Decision and tie-breaker
Use PostgreSQL direct queries, scoped schemas/roles, relational assertion graph, durable job/outbox and accounting ledgers. Optional pgvector belongs to the retrieval profile. Evidence stays on a content-addressed persistent volume. Prefer the smallest architecture satisfying the complete capability and authority contracts, not the fewest features.

## Consequences and blast radius
Fewer persistence authorities simplify consistency and recovery, but PostgreSQL workload isolation/index/queue contention must be tested. No claim that a new external vector/graph/queue service is never needed. Scope is the extracted project; no original deployment changes.

## Reversibility
Keep schema/export contracts and test future substitutions against evidence. Rebuild derived indexes; restore the matching database/object pair for incompatible data changes.

## Verification
R03-R05,R14,R29,R32,R46,R49; E02,E06,E13,E21,E28,E42,E45. Implementation and acceptance tests pending.

## Successor context (2026-10-18)

The pending verification statement above belongs to the original full-profile
proposal. Bounded PostgreSQL jobs, retrieval and reviewed intelligence shipped
under [ADR-0010](0010-durable-workflows.md),
[ADR-0018](0018-local-retrieval-reference.md) and
[ADR-0019](0019-proposals-and-local-generation.md). The compatible-route ledger
and separate settlement authority are covered by
[ADR-0042](0042-governed-compatible-cloud-route.md) through
[ADR-0044](0044-ledger-integration-boundaries.md). These accepted slices do not
close the proposed graph, accounting or recovery programme.
