# ADR-0011: Isolate model artifacts and resource authority

Status: PROPOSED. Owner: maintainer. Date: 2026-10-17.

## Context
Encoders, rerankers and generators share resources and can execute model-supplied code.

## Alternatives and no change
Copy service stack; generic unmanaged endpoint only; or tested local serving/worker contracts with resource ownership. No change retains the private prototype and remains preferable to an unsafe or unsupported extraction.

## Decision and tie-breaker
Use explicit model manifests, no implicit downloads/custom code by default, capability probes, CPU acceptance and declared GPU profiles. Bound queues and release ownership only after confirmed termination. Favor explicit contracts and failure behaviour with the fewest independently managed authorities.

## Consequences and blast radius
A single scheduler is simpler than several conflicting GPU locks; external runtimes need a conservative ownership contract. Changes apply only to the extracted project and disposable validation environments.

## Reversibility
Drain and activate versioned generations; restore previous runtime/model manifest and index alias.

## Verification
R30,R40-R42; E23,E34-E36. No implementation evidence yet.
