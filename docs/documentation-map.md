# Documentation authority and maintenance map

This map identifies what each document can establish. Read current implementation
and its callers before changing a contract; read the governing requirements and
ADRs before deciding that existing behavior is correct. A documentation claim
cannot substitute for runtime, semantic, provider or recovery evidence.

## Start here

| Question | Canonical source | How to read it |
| --- | --- | --- |
| What is implemented and tested? | [STATUS](../STATUS.md) | Current bounded behavior, explicit limits and a named verified baseline |
| What should I build next? | [Implementation backlog](implementation-backlog.md) and [roadmap](../ROADMAP.md) | Unfinished acceptance and delivery groups; a target is not a shipped feature |
| How do I work on this repository? | [AGENTS](../AGENTS.md), [CONTRIBUTING](../CONTRIBUTING.md) and [SECURITY](../SECURITY.md) | Shared agent policy, actual verification commands and disclosure boundaries |
| How do Claude/Copilot enter that policy? | [CLAUDE](../CLAUDE.md) and [Copilot instructions](../.github/copilot-instructions.md) | Thin native entry points, not separate competing engineering policies |
| What is the intended design? | [Architecture](architecture.md), [profiles](profiles/), [requirements](assurance/requirements.md) and [verification plan](testing/verification-plan.md) | Target responsibilities, testable outcomes and full scenarios; implemented refinements remain bounded |
| Why was a decision made? | [ADR register](adr/) | Read status and successor notes; retain historical decisions and evidence rather than silently rewriting them |
| What can go wrong? | [STPA](assurance/stpa.md), [secure development](security/secure-development.md) and [audit dispositions](testing/audit-remediation-2026-10-18.md) | Loss/control allocations, security boundaries and unresolved findings; no completeness or certification claim |
| Is implementation still aligned with the complete programme? | [2026-10-19 alignment review](testing/roadmap-alignment-2026-10-19.md) and [control evidence](security/control-evidence.md) | Complete requirement/scenario accounting and bounded standards selection; neither is full acceptance |
| How should an operator perform a supported task? | The runbooks below | Current CLI, identity, prerequisites, effects, failure state and recovery limits |
| What proves an earlier result? | [Testing records](testing/), [build evidence](build-evidence.md) and [dated prototype lessons](prototype-lessons.md) | Exact source/artifact/environment scope; earlier receipts never float forward to a new revision |

## Current operator contracts

| Task | Runbook |
| --- | --- |
| Collect due RSS/Atom sources and handle validators/backoff | [Scheduled acquisition](scheduled-acquisition.md) |
| Acquire explicitly permitted unmetered JSON APIs and resolve credential references | [API acquisition](api-acquisition.md) |
| Obtain a bounded machine-to-machine grant without token retention | [OAuth acquisition](oauth-acquisition.md) |
| Acquire a qualified KEV-format catalogue without exposure inference | [KEV acquisition](kev-acquisition.md) |
| Process jobs, retries and cancellation | [Durable workflows](workflows.md) |
| Build, activate and query a local retrieval generation | [Local retrieval](local-retrieval.md) |
| Generate proposals, review assertions and read cited products | [Local intelligence](local-intelligence.md) and [local chat API](local-inference-api.md) |
| Diagnose model quality without claiming adoption | [Local quality](local-quality.md) |
| Reconcile uncertain host-local inference ownership | [Inference marker safety](inference-marker-safety.md) |
| Route explicit cloud work and settle retained exposure | [Cloud routes](cloud-routes.md) |
| Validate an offline advisory observation or project stored KEV evidence | [Advisory records](advisory-records.md) and [KEV operator projection](kev-advisory-projection.md) |
| Apply retention, holds and logical retirement | [Lifecycle](lifecycle.md) |
| Capture a private checkpoint and restore an isolated target | [Recovery](recovery.md) |
| Remove unreferenced evidence objects or retired SQL derivatives | [Orphan GC](garbage-collection.md) and [SQL purge](retired-record-purge.md) |
| Install/test the bounded collector reference | [Deployment](deployment.md) and [runtime support](runtime-support.md) |
| Supervise bounded processing and assess adoption gates | [Operational profile](operational-profile.md) |
| Consume seven reads with byte-budget pagination | [MCP read contract](mcp-read-contract.md) |
| Maintain dependencies, hosted controls and publication | [Repository maintenance](repository-maintenance.md) and [publication privacy](publication-privacy.md) |
| Interpret Python/native/licence evidence | [SBOM](sbom.md), [native inventory](native-inventory.md), [licence dispositions](security/dependency-licences.md), [native policy](security/native-components.md) and [notice scope](security/supplementary-notices.md) |

## Coherence rules

1. Update the implemented runbook, STATUS and affected target/backlog allocations
   when behavior changes. Add an ADR for a material decision; do not create one
   solely to record copy editing.
2. Preserve published SQL bytes and historical JSON receipts. Fix a stale comment
   in immutable SQL through an explicit successor explanation, not a digest-changing
   edit. A historical receipt's old schema/count is not a current defect by itself.
3. State the boundary of a guarantee: command input validation, database acceptance,
   process ownership, physical work and external effects are different controls.
   A read-only tool may perform configured local inference; it cannot select an
   arbitrary model or enqueue generation merely because its name says search.
4. Separate operator attribution from authentication, provider declarations from
   independently verified sovereignty, quote coordinates from entailment, and
   private checkpoints from consumer exports.
5. Bind pass/fail/skip counts to source and environment. Distinguish syntax checks,
   fixture integration, disposable service tests and operational acceptance.
   Never repair a failing oracle by weakening the intended acceptance contract.
6. Run `scripts/check_repository.py`: it checks local Markdown references, agent
   bridges, pinned actions and the canonical STATUS schema/register facts against
   source/registers. It does not prove every prose statement or external link.
7. Review source, artifact and planned-message publication scans with the private
   denylist outside public CI. New clean scans do not erase historical findings.

The [2026-10-18 coherence audit](testing/documentation-coherence-2026-10-18.md)
records this reconciliation's scope, corrections and verification limits.


The [scheduled API service receipt](testing/scheduled-api-service-2026-10-18.json)
is historical revision-bound execution evidence for ADR-0047. The API and deployment
runbooks describe current behavior; the receipt's source/wheel/unit hashes bound
its observed disconnected two-LTS scope.

The [API fixture hardening successor](testing/scheduled-api-hardening-2026-10-18.json)
binds the subsequent TLS/verifier change to its own two-LTS run. It does not
relabel the earlier receipt or establish actual-provider or host adoption.
