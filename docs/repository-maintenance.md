# Repository maintenance policy

Scope: the public repository and its disposable synthetic CI. This is not
authorization to modify operational deployments, disclose private configuration,
call model providers or publish a package release.

## Coding assistant entry points

| Client | Entry point | Shared content |
| --- | --- | --- |
| Codex | Root AGENTS.md | Canonical constraints, code map, verification and branch lifecycle |
| Claude Code | Root CLAUDE.md with literal `@AGENTS.md` import | Loads canonical instructions rather than relying on a Markdown link being opened |
| GitHub Copilot | .github/copilot-instructions.md plus AGENTS.md where supported | Brief essential constraints and links to canonical engineering/verification guidance |

Client loading varies by version and settings. These files are guidance, not a
sandbox or a replacement for user authorization. Do not add shared credentials,
MCP endpoints, local account configuration, auto-approval settings or deployment
hooks. Keep local Claude context/settings ignored and outside publication.
Confirm loaded instructions through each client's supported diagnostics when
available; repository-file checks alone do not prove a particular client loaded them.

## Renovate update policy

`renovate.json` is the repository configuration. Review each bot onboarding or
update PR against the current base and head before integration; a generic bot
configuration is not a dependency compatibility assessment. The recurring
dependency dashboard is distinct from a mergeable update PR.

- Enable PEP621/uv.lock, GitHub Actions and Dockerfile management. These cover
  action/service images and the separately pinned validation-tool Dockerfile.
  The custom regex manager also extracts Compose image tags and digests from
  workflow environment variables; extraction validation must find both images.
- Group routine non-major Python updates and non-major CI action/image updates.
  Use a three-day release-age gate for manifest-level routine Python updates.
  The weekly uv lock maintenance is a separate complete resolution and must be
  reviewed; do not assume that gate independently delays every transitive version.
- Use Europe/Vienna scheduling before 06:00 on Monday, with at most three open
  routine Renovate PRs and one new PR per hour. Security updates may bypass normal
  bot limits. This is an eligibility window, not a
  promise of exact execution time or an embargo on manual security updates.
- Require dependency-dashboard approval for major updates. Renovate configuration
  disables bot-requested automerge; every accepted update requires current checks
  and maintainer review. GitHub auto-merge availability is a separate setting: a
  maintainer can explicitly queue an individual reviewed PR.
- Do not automatically rewrite Python support bounds, the runner generation or
  the build-system requirement. Those are tested compatibility/closure decisions.
  Revisit exclusions during dependency review; they are not permanent freezes.
- Review major caps against upstream stable releases during a complete refresh,
  including new transitive packages and the separately hashed build closure.
  Distinguish separate distribution names such as `httpcore` and `httpcore2`.
  Record supported-version exceptions and dated primary-source observations;
  lock-file success alone does not establish currency or compatibility.
- Renovate owns dependency PRs, including vulnerability remediation. Retain GitHub
  dependency alerts as detection input; disable Dependabot security-update PRs to
  avoid competing remediation branches. Security updates may run outside routine
  scheduling; findings still require review and successful acceptance checks.
- No private registry credentials, external source catalog, model inventory or
  custom post-upgrade execution is included in bot configuration.

Use the built-in `docker:pinDigests` and `helpers:pinGitHubActionDigests` presets
for container and action pinning; `:pinDigests` does not exist. The standalone
schema validator does not resolve presets and previously missed that error.
`scripts/check_renovate.sh` now runs both strict repository-mode validation and
actual local-platform preset resolution/extraction with the pinned container.
Its isolated input contains only public package, lock and workflow files. All
validator executions are unprivileged, read-only and network-disabled, with no
credentials passed. Preparing their pinned Docker image can contact the public
registry; the later validation and extraction containers run with `--network none`. Local extract stops before dependency lookup or changes.
`--exit-code-for-errors` is essential because the default CLI may return zero
after a repository configuration error. A negative control must reject the original
unknown preset with configuration-error exit 5 and the expected diagnostic; tool
upgrades must preserve or deliberately revise that tested CLI contract.

These checks establish shape and offline built-in preset resolution/extraction,
not successful hosted scheduling or correctness of proposed updates.
Observe the dependency dashboard and resulting PRs after activation. Hosted
Renovate and GitHub are external control-plane dependencies for this public code;
the JSON config, locked build and test commands remain portable to self-hosted
Renovate/CI. Do not send operational data through these services.

## Coupled build and runtime updates

`pyproject.toml`, `uv.lock` and `build-constraints.txt` serve different purposes.
The latter pins the complete isolated Hatchling build closure and approved wheel
hashes. Updating only Hatchling's requirement or one constraint breaks that closure.

For a build-tool update, review official release/artifact provenance; regenerate
the complete build-only closure with hashes from approved metadata; update the
exact build-system requirement and uv.lock consistently; then build wheel/sdist
with `--build-constraints build-constraints.txt --require-hashes`. Verify positive
builds and rejection of a wrong hash/missing transitive constraint. Run installed
core and full native acceptance. Do not replace hashes with unconstrained bounds
or claim that arbitrary build frontends enforce the designated command's policy.

Runner/Python changes require native TLS, database, process/resource and model
contract acceptance on the new profile. Model archives, native source revisions
and their checksums require coordinated provenance/compatibility review; bots must
not update one identity without the other. No runtime auto-download is authorized.

## CI and advisory auditing

Main/PR/manual foundation CI has bounded timeouts and cancels superseded runs for
the same PR/ref. Branch pushes without a PR do not run a duplicate native build.
Required checks are `repository-policy`, `renovate-policy` and
`installed-artifact`, plus the `acceptance` aggregate for advisory auditing and
disposable Compose execution. The installed-artifact check aggregates all required Ubuntu/Python native
matrix jobs (24.04/3.12 and 26.04/3.14) and fails on incomplete required work;
see [runtime support](runtime-support.md). Both call one same-commit reusable
verifier. The separate weekly/manual 3.13 compatibility workflow has no signing
permission or required-check dependency; its distinct artifacts are not admitted
by the LTS signer. A manual 3.15 dependency-only probe does not extend support.
Public diagnostics remain explicit manual activities;
concurrency queues them rather than terminating a running supervised fixture.

The PR/main and weekly/manual dependency audit exports locked core and optional ML runtime
packages and queries advisory data without resolving or fixing versions. It uses
no private inventories or credentials. Findings and advisory-service/collection
failure fail the audit; network failure is not a clean result. Reports are retained
as public CI artifacts for 30 days. Development/build tooling and native/model
components require separate review; this audit does not cover all supply chains
or establish absence of vulnerabilities. The `acceptance` gate fails when advisory data cannot be collected; a network
failure must be retried or investigated rather than reported as clean.

Do not attach untrusted public PR jobs to private/self-hosted fleet runners.
Build, test, diagnostic and advisory jobs use read-only workflow tokens and no
persisted checkout credentials. The isolated main-push attestation job alone has
OIDC and attestation write permissions; it checks same-run evidence bytes without
checking out or executing repository code. Actions and images are pinned to immutable identities. Repository settings should enforce the action allowlist and
full action SHA pins, rather than relying solely on prose.

## Repository settings and recovery

The selected policy requires PR integration, current named checks, resolved review
conversations, no force push/deletion of main and enforcement for administrators.
It intentionally requires zero additional approving reviewers for a solo
maintainer; this does not remove the maintainer's review responsibility. Signed
commits and a second reviewer are not claimed. Merge commits preserve tested
source ancestry and remain the selected integration method. The dated settings
receipts are observations, not permanent enforcement claims: the 2026-10-19
read-back found squash and GitHub auto-merge available, unlike the original
2026-10-17 state. This repair leaves their availability unchanged; it does not
select squash or grant automatic approval. Rebase remains disabled. Merged
branches can be deleted automatically while main remains protected. Branch updates
are enabled.

Allowed actions are checkout, upload-artifact, download-artifact, attest and setup-uv
at full SHAs; no other
third-party action is approved implicitly. Fork PR workflows require maintainer
approval for all external contributors. Workflow tokens cannot approve PR reviews; the isolated attestation permission
exception above does not grant pull-request or repository-content write access. Secret scanning/push protection and dependency alerts
remain enabled; private vulnerability reporting provides a confidential route.

The [2026-10-17 API receipt](testing/repository-settings.json) preserves the before
and read-back after states for this change. Settings are mutable service state.
A checked-in description alone is not proof
of enforcement: read back the actual APIs, inspect required check source app IDs
and record a dated receipt. Keep the before-state snapshot and change manifest
for recovery. Roll back settings only under authorized incident/change scope;
do not disable protection merely to merge blocked code. Reverting bot/CI config
must preserve usable required-check names or update the check policy deliberately.

The [merge-message successor receipt](testing/merge-message-settings-2026-10-19.json)
records a narrowly scoped settings repair after PR #23. Default merge and squash
messages now use the PR title and a blank body. PR titles still require review;
manual bodies and messages already stored when auto-merge was queued can override
these defaults. Review queued messages explicitly. Keep exact-message preflight
and post-merge scans; neither defaults nor a passing PR scan certify future Git
metadata. Rollback values are in the receipt, but restoring automatic PR-body
copying would restore the observed failure mode.

## Documentation maintenance

Review all tracked Markdown against current code, tests and STATUS. Check local
links/heading anchors mechanically and inspect commands/claims manually. Keep
historical test counts and ADR introductions bound to their original revisions;
add successor notes instead of rewriting them as current results. Stable S
references resolve in [references](references.md). Full E01-E51 scenario markers
remain distinct from implemented regression subsets.

An initial bounded type/security gate and source-bound build receipts now add to
these controls; see [CONTRIBUTING](../CONTRIBUTING.md) and
[build evidence](build-evidence.md). The [Python-profile SBOM](sbom.md) and
[licence evidence policy](security/dependency-licences.md) add bounded coverage;
full type coverage, native/OS/model supply-chain closure, legal redistribution
clearance, complete release assurance and the wider implementation
backlog remain open. Main-push attestations are separate from PR receipts and do
not establish operational runtime or independent quality.

The earlier runtime-compatibility increment updated SHA-pinned checkout,
artifact upload and setup-uv actions, pinned uv 0.13.1 and reviewed targeted
filelock/platformdirs patches. It retained the 1.x MCP API and native source at
that revision. [ADR-0039](adr/0039-mcp-v2-dependency-refresh.md) supersedes those
two retained selections with the MCP v2 and stable native-source transition.
Explicit compatibility review remains separate from routine bot scheduling and
release-age eligibility.

## Official guidance

- [Renovate PEP621 and uv lock maintenance](https://docs.renovatebot.com/modules/manager/pep621/)
- [Renovate configuration and release-age semantics](https://docs.renovatebot.com/configuration-options/)
- [Renovate repository-mode validation](https://docs.renovatebot.com/config-validation/)
- [Claude Code instruction imports](https://code.claude.com/docs/en/memory)
- [Codex AGENTS.md guidance](https://developers.openai.com/codex/guides/agents-md)
- [Copilot repository instructions](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions)
- [GitHub protected-branch controls](https://docs.github.com/en/rest/branches/branch-protection)

## Hosted security analysis

CodeQL default setup uses the extended query suite for Python and GitHub Actions,
with remote and local input sources. GitHub manages this generated workflow;
it is distinct from the SHA-pinned checked-in foundation workflow. Weekly analysis
and PR scans supplement local gates, and findings require source/authority review.
Do not describe a successful analysis run as proof of zero vulnerabilities.
A separate active main ruleset requires CodeQL with no bypass actors, blocking
qualifying errors and medium-or-higher security findings. This supplements the
existing required CI checks; GitHub documents limitations for diff coverage,
merge queues and Dependabot PRs under default setup. Inspect actual PR results;
this is not an all-history or universal dependency-PR guarantee.

Secret scanning, push protection, dependency alerts and private reporting remain enabled. Dependabot security-update
PRs are disabled; Renovate owns remediation PRs. Generic secret patterns are not available to this
personal public repository: a successful PATCH response still read back disabled.
Validity checks remain disabled because they contact issuing providers. Public
partner secret scanning can notify providers independently of that switch; no
private credential validation is part of this maintenance change. Local exact
private-value checks remain private and hosted scanning cannot replace them.

The [security-settings receipt](testing/security-settings-2026-10-18.json) records
observed controls, unsupported features and the initial CodeQL analysis. The
[publication/evidence ADR](adr/0036-publication-security-evidence.md) records the
trust boundary and rollback. Do not purchase a plan or move ownership merely to
turn an unavailable switch green.

The [initial CodeQL triage](testing/codeql-triage-2026-10-18.md) records actual
operator/test input authority for all 21 initial alerts, the manifest hardening
found during review, and a separate marker-race follow-up. Individual dispositions
do not suppress the query family or certify future callers.

The marker follow-up is implemented by [ADR-0037](adr/0037-inference-custody-python-sbom.md)
and [the custody protocol](inference-marker-safety.md). A successful scan does not
establish same-UID isolation or authorize removing an uncertain reservation.
Dependency PRs must update exact licence evidence through actual reviewed wheel
inspection, preserving unresolved outcomes. The maintained CycloneDX generator is
a locked development tool; its packages do not belong to the runtime inventory.

The [native evidence refinement](adr/0038-native-file-evidence-notices.md) adds an
exact recorded-ELF variant policy and separate two-package notice supplement.
Review actual wheel bytes before updating those variants; preserve unsupported
ABI distinctions and unresolved static/native/OS/model composition. V3 receipts
retain eight fixed files per leg, and the isolated main signer admits exactly
that set. The actual inline admission script is exercised by synthetic positive
and refusal fixtures, including optimization, substitution and wrong identities.

[ADR-0039](adr/0039-mcp-v2-dependency-refresh.md) governs the MCP v2 transition
and complete dependency refresh. The recurring Renovate dashboard stays open;
its pending items are reconciled by the bot after reviewed changes merge.
An updated lock also requires matching installed licence/native evidence,
modern and legacy protocol acceptance and fresh protected CI. Keep dated
currency observations separate from the revision-bound execution receipts.

The documentation audit baseline is `d01f80ac88da50c9f826b1a15cb18c75bd1db75f`.
Its [foundation run](https://github.com/rmednitzer/osint-workbench/actions/runs/39133727926)
and [CodeQL run](https://github.com/rmednitzer/osint-workbench/actions/runs/39133727466)
completed successfully. Those execution results supersede earlier pending-job
statements for the merged code; dated receipts and earlier tool inventories
retain their original revision and scope. Neither successful job status alone
nor this prose proves zero open alerts, current mutable settings, an operational
deployment or complete programme acceptance.


## Reproducible Copilot development setup

The checked-in setup workflow prepares the locked Python 3.12 retrieval/development
profile and a disposable PostgreSQL 18/pgvector service. It runs repository, lint
and static checks without downloading models or contacting inference providers.
The database credential is a public synthetic fixture, never an operational secret.
The agent receives its fixture DSN through GITHUB_ENV; this grants no fleet access.

This is an editable development environment. Full installed-wheel/native acceptance
still runs in the existing two-LTS verifier; native test-source preparation remains
explicit. Setup failure must be reported, because Copilot can continue after a
failed setup. A setup pass is not installed-artifact or semantic-quality evidence.

Foundation CI calls the same disposable Compose workflow on PRs and main. The
manual entry still requires its acknowledgement; automatic execution is restricted
to fresh GitHub-hosted runners. No private runners or operational volumes are used.
The stable acceptance aggregate rejects missing, skipped, cancelled or failed jobs.
Main signing waits for this acceptance as well as existing foundation checks.
Revert through a reviewed PR; preserve required-check names during recovery.
