# ADR-0012: Govern cloud dispatch by data, capability, sovereignty and budget

Status: PROPOSED. Owner: maintainer. Date: 2026-10-17.

## Context
API compatibility does not imply allowed disclosure, equivalent capabilities or affordable execution.

## Alternatives and no change
No cloud code; unconditional cloud fallback; or optional native/compatible adapters with policy-bound dispatch. No change retains the private prototype and remains preferable to an unsafe or unsupported extraction.

## Decision and tie-breaker
Include native OpenAI/Anthropic and declared-compatible contracts, with external endpoints/secrets. Persist route and reservation; allow only approved data/provider/jurisdiction/model/capability combinations and explicit fallback edges. Favor explicit contracts and failure behaviour with the fewest independently managed authorities.

## Consequences and blast radius
More configuration but no silent egress. Public text can contain sensitive information; DLP is only a backstop. Changes apply only to the extracted project and disposable validation environments.

## Reversibility
Disable a route without disabling local evidence reads; preserve pending remote outcomes and audit decisions.

## Verification
R43-R45,R55; E37,E38,E41,E44. No implementation evidence yet.

> Successor note (2026-10-18): [ADR-0042](0042-governed-compatible-cloud-route.md) implements one declared-compatible route under this policy model. Native adapters and fallback edges remain proposed.
