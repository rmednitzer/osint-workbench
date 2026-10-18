# ADR-0013: Maintain a reconciled operation and cost ledger

Status: PROPOSED. Owner: maintainer. Date: 2026-10-17.

## Context
Retries, streaming/batch partials, cached/reasoning tokens and missing usage complicate true spending evidence.

## Alternatives and no change
File counters; log-derived estimates only; or transactional reservations plus native usage/batch reconciliation. No change retains the private prototype and remains preferable to an unsafe or unsupported extraction.

## Decision and tie-breaker
Use logical operations/attempts, conservative reservations, unknown outcome states, per-provider usage semantics and Decimal per currency with dated pricebooks. Do not auto-replay ambiguous paid calls. Favor explicit contracts and failure behaviour with the fewest independently managed authorities.

## Consequences and blast radius
Reported usage, estimated cost and invoice evidence remain distinct; provider idempotency and cancellation have limits. Changes apply only to the extracted project and disposable validation environments.

## Reversibility
Stop new dispatch on ledger uncertainty; reconcile before releasing reservations. Export ledger schema for future replacement.

## Verification
R46,R47; E38,E42,E43. No implementation evidence yet.

> Successor note (2026-10-18): [ADR-0042](0042-governed-compatible-cloud-route.md) implements the reservation and unknown-outcome ledger for one compatible route. Batch lifecycle, native usage categories and reconciliation remain proposed. [ADR-0043](0043-remote-attempt-settlement.md) adds evidence-bound operator settlement of individual attempts; automatic usage/invoice reconciliation remains proposed.
