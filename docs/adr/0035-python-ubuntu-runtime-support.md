# ADR-0035: Test the native Python versions of both Ubuntu LTS targets

Status: ACCEPTED; runtime qualification partly superseded by ADR-0050. Date: 2026-10-17.

## Context and decision drivers

Ubuntu 24.04 defaults to Python 3.12; Ubuntu 26.04 defaults to Python 3.14.
The previous package bound excluded 3.14 and CI exercised only 24.04/3.12.
Python 3.13 was permitted without equivalent native evidence. An isolated 3.14
probe resolved the same dependency versions and built the hashed closure, but
found an advisory timestamp-normalization defect and malformed synthetic CA
extensions. Import success and wheel availability were insufficient evidence.

Drivers are LTS interoperability, explicit supply-chain custody, unchanged trust
boundaries, complete installed-artifact testing and reversible runtime changes.

## Alternatives

| Option | Consequences |
| --- | --- |
| No change | Retains 24.04 evidence but rejects the 26.04 system interpreter |
| Require only Python 3.14 | Drops the 24.04 default and adds interpreter provisioning there |
| Use managed Python 3.12 on both LTS releases | Adds separate runtime maintenance and service-path custody on 26.04 |
| Test both LTS defaults and intermediate 3.13 | Retains compatibility with more CI cost and explicit per-profile evidence; selected |

## Decision and assurance

Declare `>=3.12,<3.15` for standard CPython and keep the 3.12 language/lint target.
Require full installed-wheel/native/database jobs on 24.04/3.12, 24.04/3.13 and
26.04/3.14. Preserve the protected `installed-artifact` name with an aggregate
check that rejects incomplete matrix results. Exercise the actual reference
service independently on both LTS releases using their system Python.

Bound timestamp clock and offset components before parsing. Supply conforming
ephemeral test certificates without weakening native TLS checks. Preserve the
existing [STPA constraints](../assurance/stpa.md), scoped SQL roles, bounded
processes, immutable evidence and private-configuration boundaries.

See [runtime support](../runtime-support.md) for verification scope and limits.
Passing jobs establish only their exact source and artifacts, not operational
deployment, pretrained quality, GPU support or complete acceptance scenarios.

## Impact, reversibility and rollback

Blast radius is Python input admission, synthetic TLS fixtures, dependency
resolution and public disposable CI. The timestamp correction preserves the
already tested rejection contract across runtimes. There are no schema changes,
live collection, model downloads, provider requests or OS upgrades in this change.

Revert through a protected tested PR, preserving a usable required-check name.
Stage the previous wheel and lock under a compatible interpreter while affected
processes are stopped. Existing database/policy compatibility obligations remain;
there is no implicit data or schema rollback. Native source identity remains
unchanged. Tool/action major updates require their own reviewed pinned provenance.

## Successor context (2026-10-18)

[ADR-0039](0039-mcp-v2-dependency-refresh.md) subsequently changes the MCP
adapter/dependencies and selects the stable native-server source release while
preserving this three-profile runtime matrix. The unchanged-native-source
statement above describes this runtime-support increment only; it is not a
policy freezing all later candidates to that source. New candidates require
their own installed/native and service receipts.

## Runtime qualification successor (2026-10-19)

[ADR-0050](0050-required-lts-and-optional-python-profiles.md) supersedes the
three-profile merge/signing requirement with two native LTS profiles and separate
optional interpreter diagnostics. Earlier runtime fixes and source-bound evidence
remain valid for their named revisions. Package bounds remain `>=3.12,<3.15`.
