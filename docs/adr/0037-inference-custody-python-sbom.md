# ADR-0037: Anchor inference custody and bind Python supply-chain evidence

Status: ACCEPTED. Date: 2026-10-18.

## Context and alternatives

The marker follow-up in the dated CodeQL review identified pathname replacement
and uncertain process identity as separate risks from operator path selection.
The v1 build receipt listed installed distributions without a standard SBOM or
reviewed licence evidence. These are bounded successors to ADR-0036; they do not
establish full release, legal or operational acceptance.

| Option | Consequence |
| --- | --- |
| No change | Retains marker substitution and missing supply-chain evidence |
| New scheduler and full native/OS SBOM immediately | Requires larger deployment and component-identification work |
| New private default directory | Requires a cross-process adoption/migration protocol |
| Anchored existing custody and maintained Python SBOM generator | Bounded compatible default, enforceable evidence, explicit residual gaps; selected |

## Decision and verification

Retain the safe sticky `/tmp` default and require absolute no-follow directory
components, safe ownership/modes, and regular single-link private lock/receipt
files. Anchor operations to held descriptors. Bound and validate receipt fields,
check lock/parent identity, and remove only the observed receipt identity and
bytes. Preserve uncertain markers on write/fsync, dispatch or identity failure.
An unreadable process-start token does not prove process death. Enforce this for
encoder, reranker and native generation callers without widening MCP authority.
Document cooperative same-UID custody: a check followed by unlink is not atomic
against a malicious account peer. Actual file/process and native model tests
must discriminate replacement, permission, crash and reconciliation outcomes.

Use locked CycloneDX Python 7.5.0 to inspect the dedicated installed runtime plus
retrieval environment. Project raw metadata into a minimal public CycloneDX 1.7
document, retain the declared graph and mark composition incomplete. Validate
offline against bundled strict schemas and require a schema negative control.
Regenerate on verification to detect graph/identity tampering. Bind source,
runtime, workflow and exact inventory; never publish raw package metadata.
The generator conservatively connects installed declared requirements without
evaluating every marker/extra, so edges are not active-import evidence.

Check exact versions, publisher declarations, installed METADATA and shipped
licence/notice hashes against reviewed policy. Review selected Linux wheel
variants for each supported ABI. Separate shipped text, upstream-only proof,
unresolved bundled native closure and legal redistribution decisions. A matching
hash cannot resolve missing notices or grant approval. Dependency changes must
fail until actual new evidence is inspected; no allow-all fallback.

The v2 receipt hashes exactly two supplementary reports. Its provisional form
omits supplements to avoid a recursive digest. All tests and publication scans
must pass before retention. The isolated protected-main signer verifies the
fixed six-file set per leg, source commit and bytes; it executes no repository
code. Sign the two JSON files as provenance subjects alongside distributions
and receipts. This is not a separate CycloneDX predicate attestation. Preserve
historical v1 evidence without relabeling it.

## Scope, risks and rollback

Blast radius includes host-local inference filesystem admission, development
tooling and public synthetic CI. No database migration, source data import,
cloud/provider request, pretrained download or operational deployment occurs.
Refused unsafe legacy paths or unidentifiable receipts require private operator
recovery. Root/mount administrators and malicious same-UID processes remain
outside the admission protocol. Native binaries inside wheels, OS/container
packages, models, tools and full redistribution clearance remain incomplete.

Follow [marker recovery](../inference-marker-safety.md) before runtime rollback:
quiesce work, establish termination and resolve reservations while preserving
lock identity. Older code restores weaker checks. Evidence tooling can be
reverted through a protected PR with required checks intact. Keep prior public
artifacts and signatures source-bound; reverting cannot retract public records
or remove obligations for software already distributed.
