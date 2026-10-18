# ADR-0009: Deliver local-first profiles with explicit optional remote exceptions

Status: PROPOSED, revision 2. Owner: maintainer. Date: 2026-10-17.

## Context
The full project includes local model serving and cloud APIs while the user requires sovereignty by default.

## Alternatives and no change
Only core; reproduce the private fleet; require cloud; or independently runnable local profiles plus governed optional adapters. No change means keep the prototype private; prefer that over unsafe publication.

## Decision and tie-breaker
Provide local core/retrieval/enrichment/domain/inference operation, typed profile dependencies and generic Compose deployment. Cloud code is included but remote dispatch requires approved provider/data/budget policy; unknown/conflicting sovereignty facts deny it. No silent cloud fallback. Prefer the smallest architecture satisfying the complete capability and authority contracts, not the fewest features.

## Consequences and blast radius
Native US-provider API support is not a sovereignty approval. Hosting, model licenses/code and update authority remain relevant; client-side external AI can disclose locally returned content. Scope is the extracted project; no original deployment changes.

## Reversibility
Portable source/data/model manifests, offline approved routes and local commands allow exit/mirroring. A rejected remote route preserves local read access.

## Verification
R01,R17,R21,R30,R40-R44; E01,E14,E34-E38. Implementation and acceptance tests pending.

## Successor context (2026-10-18)

The accepted reference deployment is the explicit systemd collector under
[ADR-0026](0026-bounded-process-supervision.md) and its
[isolated enabled-source fixture](0028-isolated-enabled-source-service-fixture.md),
not a completed Compose or full-profile deployment. One governed compatible
remote route now exists under [ADR-0042](0042-governed-compatible-cloud-route.md),
with [operator settlement](0043-remote-attempt-settlement.md). Operator-declared
provider facts and synthetic contract tests do not independently prove
sovereignty, live-provider behaviour or full deployment acceptance.
