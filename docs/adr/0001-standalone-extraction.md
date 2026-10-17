# ADR-0001: Extract a standalone package through a positive allowlist

Status: PROPOSED. Date: 2026-10-17. Decision owner: repository maintainer.

## Context
The original tree combines reusable OSINT logic with operational state, deployment history and private integration. Global search-and-replace cannot establish that every disclosure path has been removed.

## Alternatives, including no change
Keep private and publish documentation only; copy and redact the full tree; or extract reviewed capabilities into a standalone package. No change means keeping the operational implementation private; it remains preferable to an unsafe or unmaintainable public export.

## Decision and tie-breaker
Extract only requirement-backed modules into a fresh local candidate, with a private source-to-public mapping and no imported operational Git history. Preserve the target repository license history unless separately authorized otherwise. Prefer the smallest option that satisfies the release acceptance contract and preserves privacy and independent operation.

## Consequences and blast radius
This costs more initial refactoring than a copy, but reduces both hidden dependencies and disclosure surfaces. Every new included module needs dependency and privacy review. Scope is the extracted project only; this decision authorizes no operational changes.

## Reversibility and rollback
The original setup is unaffected. Before publication, discard the candidate. After publication, reverting code does not retract distributed data.

## Verification
R01, R02, R16; E01, E18. All acceptance evidence remains NOT RUN until implementation. Revisit this ADR if these assumptions fail or scope changes.
