# ADR-0003: Use a capability-scoped read MCP adapter

Status: PROPOSED, revision 2. Owner: maintainer. Date: 2026-10-17.

## Context
The existing internal gateway mixes administrative/write/read methods and custom protocol semantics.

## Alternatives and no change
Expose the old gateway; provide arbitrary SQL/shell; omit MCP; or implement typed reads over application contracts. No change means keep the prototype private; prefer that over unsafe publication.

## Decision and tie-breaker
Use a maintained SDK with stdio default and versioned capability-specific read tools. Core reads are extended by enabled graph/briefing/domain/context/status profiles. Keep mutations and model job execution in typed operator CLI/worker interfaces. Prefer the smallest architecture satisfying the complete capability and authority contracts, not the fewest features.

## Consequences and blast radius
The five-tool starting subset is no longer a product cap. Tool filtering, field disclosure, SQL grants and mounts enforce authority. The optional remote HTTP profile includes the caller-authentication design and E49-E51 tests defined by ADR-0017. Scope is the extracted project; no original deployment changes.

## Reversibility
Replace the adapter without changing storage/enrichment. Remote transport follows ADR-0017; new control tools still require a separate authority and acceptance review.

## Verification
R05-R08,R19,R33,R48; E07,E08,E30,E44. Implementation and acceptance tests pending.
