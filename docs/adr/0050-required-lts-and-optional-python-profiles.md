# ADR-0050: Gate releases on native Ubuntu LTS profiles

Status: ACCEPTED. Date: 2026-10-19.

## Context and drivers

The deployment targets are Ubuntu 24.04/system Python 3.12 and Ubuntu
26.04/system Python 3.14. ADR-0035 also made intermediate Python 3.13 a required
full native profile because the package permits it. That adds CI cost without
representing another target LTS default. Permission to install on an interpreter
and a required release qualification profile are distinct contracts.

Drivers are native LTS usability, bounded CI cost, visible compatibility failures,
consistent test procedures and exact source/artifact evidence for the supported
release profiles. The user selected two required LTS profiles and optional
interpreter diagnostics. This explicitly supersedes the three-profile merge and
signing requirement of ADR-0035 and the corresponding allocation in ADR-0036;
it preserves their input/TLS fixes and historical receipts.

## Alternatives

| Option | Consequences |
| --- | --- |
| Keep all three profiles required | Stronger per-commit intermediate coverage, with unnecessary release coupling and build cost |
| Add `continue-on-error` within the required matrix | Mixes qualification and diagnostics, makes aggregate/signing semantics harder to assess; rejected |
| Remove intermediate coverage entirely | Saves cost but loses useful compatibility feedback for an admitted interpreter |
| Two required profiles and a separate optional workflow | Clear merge/signing boundary, periodic/manual compatibility feedback and common implementation; selected |

## Decision

Foundation CI requires only 24.04/3.12 and 26.04/3.14. Keep the stable
`installed-artifact` required context and reject failed, skipped or cancelled
required matrix work. A reusable same-commit workflow owns the actual installed
core, native/database/retrieval tests and producer evidence checks. It has no
signing permission and inherits no external secrets.

Python 3.13 uses that same procedure in a separate weekly/manual workflow with
`compatibility-evidence` artifact names. Its failures remain real failed jobs;
they do not block merges or LTS signing. The existing weekly advisory audit
continues to cover all three admitted interpreters; it is also outside the
per-PR required checks.

Python 3.15 is a manual, experimental locked-dependency wheel-availability probe.
It installs no application, permits no source-build fallback, rewrites no lock
and bypasses no `Requires-Python` check. The report records the exact interpreter version and release level, including
any prerelease selected by the pinned tool. Failure is useful probe feedback,
not a release failure. Success establishes neither application compatibility nor support.
Keep `>=3.12,<3.15`; a future support decision needs full application, native,
licence and deployment evidence rather than automatic upper-bound expansion.

The isolated main signer requires exactly the two same-run LTS evidence sets.
Missing required profiles and additional optional/experimental sets are rejected
before signing. The signer still checks bytes, source/run/attempt identity and
complete supplementary evidence, without checking out or executing producer code.

## Assurance, blast radius and rollback

This refines STPA SC5/U12: completeness is relative to the explicitly declared
required LTS set. Optional success cannot replace a missing required result;
optional failure cannot authorize signing incomplete LTS evidence. Regression
cases execute the actual aggregate, profile-admission and isolated signer scripts,
including missing/extra/optional evidence, wrong identity and substituted bytes.
GitHub acceptance must exercise both required reusable calls and the separate
optional workflow. The existing native service receipt remains source-bound.

Blast radius is CI routing, artifact admission and current documentation. There
are no application, dependency-lock, schema, source configuration, provider or
operational-host changes. No protection setting is relaxed. Roll back through a
protected PR restoring the previous required matrix and exact signer set together;
do not restore only one half. Historical three-profile results remain historical.

Primary pattern: [GitHub reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows).
