# Documentation coherence audit: 2026-10-18

## Scope and baseline

Baseline: `d01f80ac88da50c9f826b1a15cb18c75bd1db75f`, after merged PR #13.
Its foundation run `39133727926` and CodeQL run `39133727466` completed
successfully. This audit reconciles documentation with implemented behavior and
retained target contracts. It does not relabel earlier receipts, change a
published migration, establish a second human review or certify the full system.

Every one of the baseline's 91 tracked Markdown files was reviewed, including
all 44 ADRs. The comment/docstring inventory covered 105 tracked Python files,
all 14 SQL resources, the workflow/systemd files and other tracked configuration
comments. Cross-references were checked against actual CLI, role, migration,
worker, parser, model and evidence contracts. Files without relevant commentary
were accounted for rather than described as independently verified code.

| Review group | Baseline Markdown files | Scope |
| --- | --- | --- |
| Current overview and assurance | 8 | README, STATUS, roadmap, architecture, backlog, prototype comparison, requirements and STPA |
| Agent and contribution guidance | 6 | AGENTS, CLAUDE, CONTRIBUTING, SECURITY and both GitHub instruction/template files |
| Decisions and references | 45 | All 44 ADRs and references; original ADR status/body preserved with dated successor context where needed |
| Evidence, collection and lifecycle | 8 | Advisory, scheduling, workflows, checkpoint/recovery, lifecycle, GC, purge and operations profile |
| Local inference and retrieval | 6 | Retrieval, intelligence, quality, marker safety and both associated target profiles |
| Cloud, publication and supply chain | 10 | Cloud/profile, publication, build/SBOM/native and security documents |
| Deployment and historical testing | 8 | Deployment, runtime, maintenance and all five historical/test-plan Markdown files |

The new [documentation map](../documentation-map.md) identifies canonical current,
target, decision and historical sources. This report and that map are additional
reviewed documentation, not historical baseline files.

## Consequential corrections

- Replaced the append-only STATUS narrative with current capability/limit tables,
  source-derived schema/register facts and a clearly named evidence baseline.
- Reconciled local versus implemented governed cloud enrichment, seven-read MCP
  authority versus configured query inference, and unimplemented remote MCP.
- Corrected schema/adoption matrices, retrieval exclusions, worker retry/dedup
  semantics, evidence/reference retention and ledger-preserving purge claims.
- Distinguished operator attribution from independent review, a quoted source
  span from mention/entailment, provider declarations from verified sovereignty,
  and a bounded deadline check from physical/external-effect recall.
- Corrected file-guard descriptions to final-component protection with trusted
  parent custody; identified ordinary file I/O and cooperative timing limits.
- Reconciled Python/native inventory, SBOM/notice limitations, immutable worker
  outcomes versus separate settlement, and plaintext settlement actor/rationale.
- Added dated ADR/receipt successor context and corrected STPA controller
  allocations for routing, accounting, model admission, orphan GC and publication.
- Corrected the reference-service feed oracle: both feed items are processed,
  but the unchanged item reuses its head, leaving three retained versions/jobs.
  Added a native SQL/parser/CAS regression using the exact synthetic service bytes.
- Added bounded repository checks that derive schema/profile/checkpoint facts
  from Python declarations and count consecutive ADR/requirement/scenario IDs.
  Negative fixtures demonstrate stale claims and ambiguous/missing inputs fail.

Application behavior is unchanged by the comment/docstring edits. Intentional
executable changes are confined to the repository facts checker, its tests and
the stale service-harness oracle plus its regression. Published SQL, lockfiles,
dependency selections, hosted permissions and historical JSON receipts remain
unchanged.

README is the wheel's long description. Its edit changes this project's METADATA
bytes, so the active licence policy's own-project metadata evidence is refreshed
only after comparing the actual old/new wheels: metadata headers and the shipped
Apache-2.0 text are identical; the reviewed README payload is the sole metadata
change. No third-party approval or historical archive evidence is regenerated.

## Verification and unresolved scope

Required candidate CI owns installed-wheel native results and artifact identities;
this audit record is not an execution receipt. The separate service-only workflow
uses `profile=reference-service` on both supported Ubuntu LTS defaults. It performs
synthetic root/systemd/namespace/database fixture work only on disposable hosted
runners and skips the pretrained encoder diagnostic. Its current result must be
read from the candidate's named run rather than inferred from old service receipts.

The [new service receipt](documentation-service-2026-10-18.json) records run
`39136643892`, tested source `ebdbf666e0f4001dca59ce8760386aae80408d61` and both
installed-wheel digests. Both LTS service jobs passed; the encoder job was
intentionally not selected. The recorded positive and negative fixture outcomes
are bounded observations, not whole-host or provider acceptance.

Local checks cover Markdown links, source/register drift controls, syntax/lint,
static security/type boundaries, relevant offline tests and publication scans.
Native database and privileged service outcomes are reported separately in the
candidate PR. Source/read-only review does not prove all comments, requirements,
external links, semantic quality, sovereignty, operational recovery or full E01–E51.

Known open implementation findings remain in
[the audit dispositions](audit-remediation-2026-10-18.md) and
[the backlog](../implementation-backlog.md), including quote-label support,
self-review authority, MCP size-aware pagination and special-token handling.
No operational prototype, provider or private host was modified. The historical
PR #9 session-link metadata finding remains; new clean scans do not clear it.
