# ADR-0010: Durable jobs, fencing and transactional outbox

Status: PROPOSED. Owner: maintainer. Date: 2026-10-17.

## Context
Enrichment, indexing, batch imports and reports must survive crashes and overlapping workers.

## Alternatives and no change
Ad hoc timers/files; external workflow engine/message broker; or PostgreSQL jobs/outbox initially. No change retains the private prototype and remains preferable to an unsafe or unsupported extraction.

## Decision and tie-breaker
Use durable job/attempt/lease/fencing records, transactional downstream enqueue, bounded retries and idempotent acceptance. Do not claim exactly-once remote execution. Favor explicit contracts and failure behaviour with the fewest independently managed authorities.

## Consequences and blast radius
Lease expiry, clock assumptions, cancellation and queue contention require tests; an external broker is reconsidered only on evidence. Changes apply only to the extracted project and disposable validation environments.

## Reversibility
Version job records and drain/restore safely; preserve pending/unknown outcomes instead of deleting them.

## Verification
R33,R34,R47; E06,E25,E26,E43. No implementation evidence yet.
