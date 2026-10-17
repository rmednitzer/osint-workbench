# ADR-0016: Treat retention and outbound publication as separate controlled effects

Status: PROPOSED. Owner: maintainer. Date: 2026-10-17.

## Context
Deleting a live row cannot delete all embeddings, reports, backups or remote copies; publication can leak private context.

## Alternatives and no change
Raw purge/export scripts; fully automatic publication; or reachability/hold-aware lifecycle and staged optional publisher. No change retains the private prototype and remains preferable to an unsafe or unsupported extraction.

## Decision and tie-breaker
Propagate tombstones to derivatives/caches/jobs, enforce holds and restored-deletion policy. Publish only validated selected bundles with immutable IDs and receipt reconciliation; disabled by default. Favor explicit contracts and failure behaviour with the fewest independently managed authorities.

## Consequences and blast radius
Immutable/public/provider/backed-up copies have explicit deletion limits. No anonymity or global-erasure claim. Changes apply only to the extracted project and disposable validation environments.

## Reversibility
Stop publication/GC, restore accepted pair and reconcile; credential rotation precedes history cleanup after disclosure.

## Verification
R22,R29,R51,R54; E17,E18,E39,E47,E48. No implementation evidence yet.
