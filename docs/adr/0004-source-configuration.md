# ADR-0004: Keep operational source selection outside the repository

Status: PROPOSED. Date: 2026-10-17. Decision owner: repository maintainer.

## Context
The actual source catalogue and adapter URLs reveal interests and integration details and may contain credentials or tracking parameters.

## Alternatives, including no change
Bundle existing feeds; bundle a curated public list; or ship an empty registry and synthetic examples. No change means keeping the operational implementation private; it remains preferable to an unsafe or unmaintainable public export.

## Decision and tie-breaker
Ship sources: [] and synthetic fixtures only. Supply real URLs at runtime through a mounted private configuration or source registry. Generic HTTP/RSS adapters have no live acquisition URLs hardcoded. Separate source configuration, credential files and ordinary non-secret limits. Prefer the smallest option that satisfies the release acceptance contract and preserves privacy and independent operation.

## Consequences and blast radius
The demo must work without external feeds. Public dependency registries, standards references and placeholder URLs are classified separately; they are not evidence that an operational source URL is safe to publish. Scope is the extracted project only; this decision authorizes no operational changes.

## Reversibility and rollback
A future curated source pack is a separate opt-in artifact with its own review. Removing it must not break core installation.

## Verification
R02, R09, R16; E01, E09, E18. All acceptance evidence remains NOT RUN until implementation. Revisit this ADR if these assumptions fail or scope changes.
> Planning-baseline note (2026-10-17): NOT RUN statements in this ADR describe the original planning state. Current bounded implementation evidence is indexed by [STATUS](../../STATUS.md); it does not close the full programme.
