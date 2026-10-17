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

`renovate.json` is the repository configuration. The existing onboarding PR is
reviewed and refreshed against current main before integration; its generic
configuration is not a dependency compatibility assessment.

- Enable PEP621/uv.lock, GitHub Actions and Dockerfile management. These cover
  action/service images and the separately pinned validation-tool Dockerfile.
- Group routine non-major Python updates and non-major CI action/image updates.
  Use a three-day release-age gate for manifest-level routine Python updates.
  The weekly uv lock maintenance is a separate complete resolution and must be
  reviewed; do not assume that gate independently delays every transitive version.
- Use Europe/Vienna scheduling before 06:00 on Monday, with at most three open
  routine Renovate PRs and one new PR per hour. Security updates may bypass normal
  bot limits. This is an eligibility window, not a
  promise of exact execution time or an embargo on manual security updates.
- Require dependency-dashboard approval for major updates. Disable automerge;
  every accepted update requires current checks and maintainer review.
- Do not automatically rewrite Python support bounds, the runner generation or
  the build-system requirement. Those are tested compatibility/closure decisions.
  Revisit exclusions during dependency review; they are not permanent freezes.
- Retain GitHub dependency alerts and Dependabot security fixes. Security PRs may
  arrive outside routine Renovate scheduling. Do not automatically suppress
  duplicate advisories; inspect and reconcile equivalent update branches.
- No private registry credentials, external source catalog, model inventory or
  custom post-upgrade execution is included in bot configuration.

Use the built-in `docker:pinDigests` and `helpers:pinGitHubActionDigests` presets
for container and action pinning; `:pinDigests` does not exist. The standalone
schema validator does not resolve presets and previously missed that error.
`scripts/check_renovate.sh` now runs both strict repository-mode validation and
actual local-platform preset resolution/extraction with the pinned container.
Its isolated input contains only public package, lock and workflow files. All
validation containers are unprivileged, read-only and network-disabled, with no
credentials passed. Local extract stops before dependency lookup or changes.
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
`installed-artifact`. The latter aggregates all required Ubuntu/Python native
matrix jobs and fails on incomplete matrix work; see [runtime support](runtime-support.md).
Public diagnostics remain explicit manual activities;
concurrency queues them rather than terminating a running supervised fixture.

The weekly/manual dependency audit exports locked core and optional ML runtime
packages and queries advisory data without resolving or fixing versions. It uses
no private inventories or credentials. Findings and advisory-service/collection
failure fail the audit; network failure is not a clean result. Reports are retained
as public CI artifacts for 30 days. Development/build tooling and native/model
components require separate review; this audit does not cover all supply chains
or establish absence of vulnerabilities. It is not a required per-PR network gate.

Do not attach untrusted public PR jobs to private/self-hosted fleet runners.
Workflows use read-only tokens and no persisted checkout credentials; actions and
images are immutable. Repository settings should enforce the action allowlist and
full action SHA pins, rather than relying solely on prose.

## Repository settings and recovery

The selected policy requires PR integration, current named checks, resolved review
conversations, no force push/deletion of main and enforcement for administrators.
It intentionally requires zero additional approving reviewers for a solo
maintainer; this does not remove the maintainer's review responsibility. Signed
commits and a second reviewer are not claimed. Merge commits preserve tested
source ancestry; squash/rebase merge paths are disabled. Merged branches can be
deleted automatically while main remains protected. Branch updates are enabled.

Allowed actions are checkout, upload-artifact and setup-uv at full SHAs; no other
third-party action is approved implicitly. Fork PR workflows require maintainer
approval for all external contributors. Workflow tokens remain read-only and
cannot approve PR reviews. Secret scanning/push protection and dependency alerts
remain enabled; private vulnerability reporting provides a confidential route.

The [2026-10-17 API receipt](testing/repository-settings.json) preserves the before
and read-back after states for this change. Settings are mutable service state.
A checked-in description alone is not proof
of enforcement: read back the actual APIs, inspect required check source app IDs
and record a dated receipt. Keep the before-state snapshot and change manifest
for recovery. Roll back settings only under authorized incident/change scope;
do not disable protection merely to merge blocked code. Reverting bot/CI config
must preserve usable required-check names or update the check policy deliberately.

## Documentation maintenance

Review all tracked Markdown against current code, tests and STATUS. Check local
links/heading anchors mechanically and inspect commands/claims manually. Keep
historical test counts and ADR introductions bound to their original revisions;
add successor notes instead of rewriting them as current results. Stable S
references resolve in [references](references.md). Full E01-E51 scenario markers
remain distinct from implemented regression subsets.

Current dependency and repository controls do not close type/static analysis,
licence/SBOM/provenance dispositions, complete release assurance or the wider
implementation backlog.

The reviewed runtime-compatibility change updates SHA-pinned checkout, artifact
upload and setup-uv actions, and pins uv 0.13.1. It also reviews the two targeted
filelock/platformdirs patch updates. This explicit compatibility review is separate
from routine bot scheduling/release-age eligibility; MCP remains on its reviewed
1.x API contract and native source/checksum remain unchanged.

## Official guidance

- [Renovate PEP621 and uv lock maintenance](https://docs.renovatebot.com/modules/manager/pep621/)
- [Renovate configuration and release-age semantics](https://docs.renovatebot.com/configuration-options/)
- [Renovate repository-mode validation](https://docs.renovatebot.com/config-validation/)
- [Claude Code instruction imports](https://code.claude.com/docs/en/memory)
- [Codex AGENTS.md guidance](https://developers.openai.com/codex/guides/agents-md)
- [Copilot repository instructions](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions)
- [GitHub protected-branch controls](https://docs.github.com/en/rest/branches/branch-protection)
