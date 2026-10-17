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
R22,R29,R51,R54; E17,E18,E39,E47,E48. ADR-0021 implements the bounded logical
retention/hold/tombstone and restore-policy subset. ADR-0022 adds reviewed orphan
cleanup. Full retained-record purge, backup expiry and outbound publication remain
proposed; its revision-bound evidence does not close this ADR's
whole target scope.
> Implementation follow-up (2026-10-17): [ADR-0032](0032-transactional-retired-record-purge.md) implements bounded retired-record SQL purge, while [recovery](../recovery.md) and [lifecycle](../lifecycle.md) have bounded implementations. Full erasure, public export/publishing and operational recovery remain open.
