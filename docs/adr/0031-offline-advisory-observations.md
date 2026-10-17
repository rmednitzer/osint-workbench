# ADR-0031: Preserve attributed advisory observations before assessment

Status: ACCEPTED for the bounded offline envelope. Owner: maintainer. Date: 2026-10-17.

## Context and requirements

R36/R37 and the U19/C19 hazard constraint separate source claims from target
applicability, exposure and remediation policy. CVSS, EPSS and exploitation
observations can conflict or refer to different dates and publishers. A normalized
record must preserve those distinctions before database/adaptor integration.
This increment contributes to E31; it does not close E31, E32 or the vulnerability
profile. There is no live acquisition, package matching or operational action.

## Alternatives and decision

| Alternative | Benefit | Cost and boundary |
| --- | --- | --- |
| No change; retain raw evidence only | Avoids premature normalized semantics | No independently testable domain contract for later adapters |
| Adopt complete upstream schemas directly | Retains upstream vocabulary | Several incompatible schemas still need explicit source/time/evidence boundaries; it does not supply local applicability |
| Bounded normalized observation envelope | Small offline contract; conflicts and attribution survive round trips | A deliberately partial projection; future adapters must preserve raw evidence and explicitly report unsupported source fields |

Choose the bounded envelope for authored normalized input. Keep the raw snapshot
reference external and retain a publisher and evidence references on each score
or exploitation observation, and bind each observation to a CVE declared by the
envelope. Reject numeric lexemes that lose decimal value at the canonical
binary64 wire boundary, including underflow and rounded range violations. A reference is a claim about a location, not proof
that bytes exist or support a statement. Do not infer trust from a publisher label,
a CVE identifier, a score or a record's presence. A later adapter requires its own
upstream-schema mapping and loss/partial-outcome tests.

Use strict frozen Pydantic models, immutable nested collections and bounded UTF-8
JSON input. Reject unknown keys, duplicate object keys, malformed/nonfinite values
and excessive structure without echoing input through the parser's public error.
Canonical output is the project's deterministic JSON encoding; it is not an
RFC 8785, STIX, VEX or evidence-signature conformance claim. Preserve separate
publication, modification, observation, score and reported-exploitation dates.

## Consequences and verification

The envelope deliberately omits affected-product/range expressions and target
inventory. It cannot establish catalogue completeness, score/vector consistency,
registry existence, active exploitation, source independence or exposure. Raw
Pydantic validation diagnostics are not a safe logging interface for private
input; callers use the bounded parser's fixed public failure instead.

Acceptance requires installed-wheel positive and adversarial tests, conflicting
observations retained, deterministic round trip, strict primitive/count/span/date
bounds, and redacted parser errors. The revision-bound verification receipt records
executed checks. Authored fixtures establish contract behaviour, not upstream
interoperability or live intelligence quality.

## Blast radius, reversibility and rollback

Only an opt-in Python module and synthetic tests/documentation are added. No
migration, existing record rewrite, CLI/MCP registration, runtime download or
network dispatch is introduced. Existing collection, storage and inference paths
remain independent. Reverting this increment removes the envelope; future stored
consumers must introduce explicit format compatibility before adoption. Do not
reuse a format version for an incompatible schema.
