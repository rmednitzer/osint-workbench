# ADR-0007: Verify complete installed profiles with independent oracles

Status: PROPOSED, revision 2. Owner: maintainer. Date: 2026-10-17.

## Context
A mock-only reduced pipeline would not demonstrate full integration; cloud fixtures also cannot establish live-provider behaviour.

## Alternatives and no change
Reuse existing tests; smoke-test only core; rely on model judges; or combine functional, quality, failure and real-boundary tests. No change means keep the prototype private; prefer that over unsafe publication.

## Decision and tie-breaker
Test built artifacts against disposable PostgreSQL, controlled HTTP sources, real MCP client and real local models. Add independent quality sets, resource tests, provider contract harness and explicitly separated live-provider/hardware verification. Fail unexpected mandatory skips. Prefer the smallest architecture satisfying the complete capability and authority contracts, not the fewest features.

## Consequences and blast radius
Requires more CI profiles and conditional hardware/live tests. Evidence must state what ran; a missing live test is outstanding, not a fabricated pass. Scope is the extracted project; no original deployment changes.

## Reversibility
Keep local commands independent of CI provider; preserve revision-bound evidence and rerun affected/full release gates when candidate bytes change.

## Verification
R13,R18,R24,R53; E01-E51. Implementation and acceptance tests pending.
