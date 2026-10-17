# ADR-0017: Support authenticated remote MCP as an explicit profile

Status: PROPOSED. Owner: maintainer. Date: 2026-10-17.

## Context
Stdio serves local clients, while remotely connected assistants require a standalone remote transport rather than the private internal gateway.

## Alternatives and no change
Stdio only; unauthenticated HTTP/proxy; or optional authenticated Streamable HTTP with maintained security components. No change retains the private prototype and remains preferable to an unsafe or unsupported extraction.

## Decision and tie-breaker
Implement stdio plus TLS-protected Streamable HTTP with maintained OAuth/resource-server integration, validated issuer/audience/scopes, principal-to-workspace authorization and bounded sessions/requests. Never pass client tokens through to upstream providers. Favor explicit contracts and failure behaviour with the fewest independently managed authorities.

## Consequences and blast radius
Adds identity/deployment/client tests; single-operator initial scope does not excuse cross-principal/session checks. No public listener is activated by this plan. Changes apply only to the extracted project and disposable validation environments.

## Reversibility
Disable the remote profile and revoke its credentials/sessions while preserving local reads; retain identical application read semantics across transports.

## Verification
R56-R58; E49-E51. No implementation evidence yet.
