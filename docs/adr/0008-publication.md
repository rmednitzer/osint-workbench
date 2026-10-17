# ADR-0008: Bind privacy review to the exact release bytes

Status: PROPOSED. Date: 2026-10-17. Decision owner: repository maintainer.

## Context
A clean working tree scan does not cover earlier commits, commit metadata, package metadata, logs, images or build layers.

## Alternatives, including no change
Trust .gitignore/secret scanning; redact a finished archive; or build from an allowlisted staged candidate and scan every outgoing surface. No change means keeping the operational implementation private; it remains preferable to an unsafe or unmaintainable public export.

## Decision and tie-breaker
Use a positive publication manifest, generic public scanners and a private local identifier/source catalogue check. Scan all reachable candidate history, changed metadata, unpacked distributables and generated outputs. Bind receipts to commit/tree and artifact hashes; any change invalidates them. Prefer the smallest option that satisfies the release acceptance contract and preserves privacy and independent operation.

## Consequences and blast radius
Private denylist values and raw scan findings must never be supplied to public CI. False positives require explicit narrow dispositions. The existing public author email needs its own recorded decision. Scope is the extracted project only; this decision authorizes no operational changes.

## Reversibility and rollback
Block before push on findings. After disclosure, rotate secrets first and assess recipients/caches; history rewrite or deletion needs separate authorization.

## Verification
R16, R18; E16, E18. All acceptance evidence remains NOT RUN until implementation. Revisit this ADR if these assumptions fail or scope changes.
> Planning-baseline note (2026-10-17): NOT RUN statements below describe the original planning state. Current bounded implementation evidence is indexed by [STATUS](../../STATUS.md); it does not close the full programme.
