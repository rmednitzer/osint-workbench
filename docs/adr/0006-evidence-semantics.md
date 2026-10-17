# ADR-0006: Model evidence and derived claims without false verification

Status: PROPOSED, revision 2. Owner: maintainer. Date: 2026-10-17.

## Context
The prototype has length/overlap heuristics, fixed confidence values and a reproduced Unicode offset defect.

## Alternatives and no change
Retain current labels; omit enrichment; or create independent evidence/derivation/review semantics with exact coordinate maps. No change means keep the prototype private; prefer that over unsafe publication.

## Decision and tie-breaker
Preserve acquisition/extraction/integrity/freshness separately. Support graph and claim proposals, accepted/rejected/quarantined/superseded states, source spans, contradictions and review rationale. Never treat a matching quotation, hash or model agreement as factual truth. Prefer the smallest architecture satisfying the complete capability and authority contracts, not the fewest features.

## Consequences and blast radius
More explicit states require downstream handling but preserve provenance and abstention. Probability-like numbers need calibrated definitions; absent that use named dispositions. Scope is the extracted project; no original deployment changes.

## Reversibility
Version contracts and regenerate derived records from immutable snapshots; do not silently rewrite historic evidence or claim states.

## Verification
R04,R11,R12,R27,R32-R35; E03,E11,E25-E30. Implementation and acceptance tests pending.
