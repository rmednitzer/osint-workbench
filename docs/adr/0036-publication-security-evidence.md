# ADR-0036: Bind publication checks and build evidence to reviewed source

Status: ACCEPTED; runtime qualification partly superseded by ADR-0050. Date: 2026-10-18.

## Context and drivers

File and archive scans did not inspect new Git messages or identities. CI printed
artifact hashes without retaining the distributions. Formatting and tests did not
provide a type or static security gate. Hosted code scanning was not configured.
The threat is accidental disclosure, undetected unsafe changes, or evidence that
cannot be related to the actual tested source. These additions implement part of
the existing build/publication threat boundary; they do not close full release
assurance, independent quality evaluation or operational safety acceptance.

## Alternatives

| Option | Consequences |
| --- | --- |
| No change | Preserves the observed publication and evidence gaps |
| Strict typing of all modules and a complete release system immediately | Larger unrelated refactoring and difficult-to-review trust changes |
| Blanket scanner exclusions or unsigned hashes called provenance | Obscures meaningful findings and overstates evidence |
| Incremental enforced checks, retained artifacts and isolated main signing | Bounded coverage with explicit residual gaps; selected |

## Decision and verification

Scan explicit ancestor-to-HEAD commit metadata, with sanitized findings and
narrow, explicit reuse of identities already present in the reviewed base commit.
Private exact-value policy stays outside the repository and public CI. Scan source
and packages independently. Existing public history is not rewritten.

Apply the initial type gate to four named boundary modules and security lint to
application source. Review three exact heuristic exceptions at their enforcement
code. Prove that both tools reject actual negative controls. Existing native,
installed-wheel and database tests remain required on all three runtime profiles.

After those tests and archive scans succeed, retain wheel/sdist and an offline
source/runtime/hash/dependency-inventory receipt for 30 days. Verify the receipt by
recomputation. Declared licence metadata is not a legal disposition or a complete
SBOM. Do not call its ordinary checksum a signature.

Only a successful push to protected main can start the separate attestation job.
It downloads artifacts from that same workflow run and executes no repository
code. Only this job receives OIDC and attestation write permissions. PR and manual
runs retain unsigned evidence without signing authority. Retain the portable
signature bundle and verify it against the expected repository/workflow and
source revision. Pin the two artifact actions and expand the existing allowlist
only for them. GitHub's generated default CodeQL workflow is a separately managed
service, not a checked-in action-pin guarantee.

Enable CodeQL's extended Python/Actions queries with local and remote inputs;
triage findings against actual authority and callers. Never dismiss a finding
merely to merge. Keep hosted configuration/read-back evidence separate from test
results. Unsupported paid/organization features remain explicit limitations.

## Impact, residual risk and rollback

Blast radius is public repository metadata policy, development tooling and public
synthetic CI. Model-manifest input admission also rejects blocking/nonregular files with bounded,
sanitized errors; actual CLI and growth tests cover this review finding.
There are no schema changes, operational deployment, collection,
provider requests or pretrained model downloads. Hosted analysis/signatures depend
on GitHub and, for public provenance, Sigstore's public infrastructure. Retention
expires; this is not a package release or durable archival service.

Existing STPA publication constraints remain applicable: no private operational
inputs, no expansion of MCP authority and no inference that green tests establish
all programme requirements. Tool false negatives, runner compromise, undeclared
native components, licensing decisions and independent quality remain open.

Roll back through a protected PR while preserving required check names. Restore
settings from the dated sanitized before-state only under the applicable change
scope. Do not disable protections to merge. Previously public metadata and public
attestations cannot be made private by reverting a workflow.

## Successor context (2026-10-18)

[ADR-0037](0037-inference-custody-python-sbom.md) and
[ADR-0038](0038-native-file-evidence-notices.md) add maintained Python SBOM,
licence/native review and notices to the retained and signed evidence set.
[ADR-0044](0044-ledger-integration-boundaries.md) adds planned-message preflight.
The original plain-inventory and publication scope here is a baseline, not a
claim that it is the whole current evidence set or that historical disclosure
findings have been cleared.

## Runtime qualification successor (2026-10-19)

[ADR-0050](0050-required-lts-and-optional-python-profiles.md) supersedes the
three-profile merge/signing requirement with two native LTS profiles and separate
optional interpreter diagnostics. Earlier runtime fixes and source-bound evidence
remain valid for their named revisions. Package bounds remain `>=3.12,<3.15`.
