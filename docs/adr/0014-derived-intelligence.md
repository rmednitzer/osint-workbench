# ADR-0014: Separate source facts, model proposals and domain interpretations

Status: PROPOSED. Owner: maintainer. Date: 2026-10-17.

## Context
Graph/briefing and vulnerability/legal outputs can convert plausible text into unsupported operational conclusions.

## Alternatives and no change
Copy heuristic outputs; omit derived intelligence; or validate typed proposals with provenance and abstention. No change retains the private prototype and remains preferable to an unsafe or unsupported extraction.

## Decision and tie-breaker
Use deterministic authoritative-schema projections and model proposals with versioned evidence spans, lifecycle, contradictions and review. Domain applicability and remediation/legal judgments remain distinct. Favor explicit contracts and failure behaviour with the fewest independently managed authorities.

## Consequences and blast radius
Stricter acceptance can reduce coverage; report abstention and recall rather than relaxing support gates silently. Changes apply only to the extracted project and disposable validation environments.

## Reversibility
Recompute derived generations and withdraw/supersede products; immutable source snapshots survive.

## Verification
R27,R32,R35-R39; E27-E33,E40. Local typed proposals, reviewed graph assertions and cited digests now have PostgreSQL/MCP tests; see ADR-0019. General graph resolution, domains and semantic-quality acceptance remain pending.
