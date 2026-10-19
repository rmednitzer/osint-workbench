# Roadmap and engineering alignment review: 2026-10-19

## Decision and baseline

The programme remains aligned with the intended evidence-oriented, self-hostable
integration workbench. Its complete reference implementation is unfinished.
The old README's warning was substantively valid, but its capability summary
understated implemented authenticated acquisition, retrieval and supervised
service paths. A clearer inventory replaces that wording without dropping local,
cloud, domain, JavaScript-source, remote-MCP or publication scope.

Review baseline: `6fce1feb09e2f1474ba6cc2b7bd89fcfc805abb2`.
[Foundation run 39230228564](https://github.com/rmednitzer/osint-workbench/actions/runs/39230228564)
and [CodeQL run 39230228550](https://github.com/rmednitzer/osint-workbench/actions/runs/39230228550)
completed successfully for that source. These are baseline observations, not
acceptance of the successor changes described below. Candidate and post-merge
results, wheel/lock identities and service evidence belong to the change's PR
and same-revision build manifests. No historical receipt is relabelled.

## Review method and limits

The review cross-checked the current overview, roadmap/backlog, architecture,
four target profiles, R01–R58, E01–E51, selected STPA refinements, agent/contribution
policy, secure-development references and relevant operator/build runbooks.
Source tracing covered CLI/MCP dispatch and reader authority; feed/API/OAuth
acquisition and credential custody; job/fence/acceptance boundaries; local model
admission/tokenization and retrieval; review/product semantics; lifecycle/recovery;
and cloud accounting. Existing tests were inspected as counterevidence, including
known issues that later increments had already corrected.

This is a bounded source and evidence review, not an independent line-by-line
review of every application, dependency, native library or historical comment.
Markdown/reference and static checks provide separate mechanical coverage.
The table below is a primary accounting of scope: every requirement and full
scenario is assigned once so none disappears from the review. Cross-cutting
allocations remain in the canonical [requirements](../assurance/requirements.md),
[STPA](../assurance/stpa.md) and [verification plan](verification-plan.md).
Assignments, tests and source links do not themselves close a requirement or
scenario.

## Complete scope accounting

All listed workstreams retain **open full acceptance**. Paths are representative
implementation/test anchors, not a claim that every target is implemented.

| Workstream | Requirements | Full scenarios | Bounded implementation, executable anchors and remaining work |
| --- | --- | --- | --- |
| Acquisition and evidence | R03, R04, R09, R12, R15, R25, R26, R52 | E02, E05, E06, E09, E10, E12, E19, E20, E40 | [Collector](../../src/osint_workbench/collection.py), [API](../../src/osint_workbench/api_acquisition.py), [TLS/acquisition cases](../../tests/test_tls_collection.py), [OAuth cases](../../tests/test_oauth.py). Broader extraction/JavaScript, restricted rights, shared-host quotas and provider/Internet acceptance remain open. |
| Retrieval | R10, R28, R29, R31 | E04, E11, E21, E22, E23 | [Vector index](../../src/osint_workbench/vector_index.py), [native index cases](../../tests/test_vector_index.py), [query coalescing](../../tests/test_query_flights.py). Exact/RRF and generations exist; incremental backfill, scoped persistent caches, ANN/oracle and scale acceptance remain open. |
| Local inference and resources | R30, R40, R41, R42, R45 | E34, E35, E36, E41 | [Generation](../../src/osint_workbench/local_generation.py), [admission](../../src/osint_workbench/inference_state.py), [native token cases](../../tests/test_generation_tokens.py), [child lifetime](../../tests/test_inference_child_lifetime.py). Synthetic execution is implemented; adopted useful models, full hard resource/fairness/termination and acceleration evidence remain open. |
| Enrichment, graph and context | R27, R32, R33, R34, R48 | E25, E26, E27, E28, E30, E39 | [Proposals/reviews](../../src/osint_workbench/intelligence.py), [intelligence cases](../../tests/test_intelligence.py), [workflow cases](../../tests/test_workflows.py). Source spans/fences exist; independent review, label support, aliases/reversible merges, richer workflows and workspace context remain open. |
| Briefings and quality | R11, R35, R53 | E24, E29 | [Evaluation](../../src/osint_workbench/evaluation.py), [diagnostics](../../src/osint_workbench/quality.py), [quality cases](../../tests/test_quality.py). Cited digests and negative numeric gates exist; independent held-out relevance/support/abstention, diversity and useful analysis remain open. |
| Vulnerability intelligence | R36, R37 | E31, E32 | [Advisory envelope](../../src/osint_workbench/advisory.py), [KEV mapping](../../src/osint_workbench/kev.py), [advisory cases](../../tests/test_advisory.py), [KEV cases](../../tests/test_kev.py). Qualified upstream persistence, retractions, ecosystem ranges and local-asset applicability/prioritization remain open. |
| Regulatory intelligence | R38, R39 | E33 | [Domain specification](../profiles/enrichment-and-domains.md#regulatory-profile). No implemented regulatory record/transition/applicability engine; multilingual source, legal-state/date and procedure acceptance remain open. |
| Governed cloud | R43, R44, R55 | E37, E44 | [Cloud route](../../src/osint_workbench/cloud.py), [denial/fixture cases](../../tests/test_cloud.py), [credential cases](../../tests/test_cloud_credentials.py). Explicit compatible extraction exists; native adapters, wider capabilities, separate dispatch and provider/sovereignty acceptance remain open. |
| Accounting and batches | R46, R47 | E38, E42, E43 | [Ledger](../../src/osint_workbench/cloud.py), [settlement cases](../../tests/test_cloud_settlement.py). Reservations/unknown outcomes/operator settlement exist; invoice import/correction, native token categories and durable batch workflows remain open. |
| MCP and authorization | R05, R06, R07, R08, R56, R57, R58 | E07, E08, E49, E50, E51 | [Seven-read adapter](../../src/osint_workbench/mcp_server.py), [reader grants](../../tests/test_reader_authority.py), [actual stdio protocol](../../tests/test_mcp_protocol.py). Remote TLS/auth/session/principal isolation and independent assistant-client acceptance remain open. |
| Recovery and lifecycle | R14, R49, R54 | E13, E45, E48 | [Recovery](../../src/osint_workbench/recovery.py), [lifecycle](../../src/osint_workbench/lifecycle.py), [composed recovery cases](../../tests/test_operational_recovery.py), [purge faults](../../tests/test_purge_boundary_faults.py). Bounded logical recovery exists; independent policy custody, all-copy/backup expiry, full-host/PITR and representative volume remain open. |
| Consumer export and publication | R22, R51 | E03, E17, E47 | [Target lifecycle/publication](../profiles/enrichment-and-domains.md#specialist-source-adapters-and-publication). Private checkpoints and existing cited products do not implement selected-field consumer export or an outbound publisher; disclosure/receipt/reconciliation acceptance remains open. |
| Deployment and operations | R01, R17, R21, R50 | E01, E14, E15, E46 | [Supervised profile](../operational-profile.md), [health cases](../../tests/test_health.py), [service harness](../../scripts/test_reference_deployment.py). Non-root templates and disposable acceptance exist; complete provisioning, monitoring response, capacity and target-host/recovery acceptance remain open. |
| Secure development and publication privacy | R02, R13, R16, R18, R19, R20, R23, R24 | E16, E18 | [Control evidence](../security/control-evidence.md), [publication cases](../../tests/test_commit_publication.py), [signer refusal cases](../../tests/test_evidence_workflow.py). Locked builds, scans and signing exist; complete type/static/control assessment, native/OS/model composition, redistribution and full release evidence remain open. |

This accounting covers **58 distinct requirements and 51 distinct scenarios**.
The backlog remains the canonical unfinished-work ledger. NOT RUN full-scenario
markers remain valid: neither the regression count nor this mapping establishes
complete scenario execution. Core schema 11, retrieval profile 4, checkpoint
format 2 and 50 ADRs are unchanged by this increment.

## Corrected findings

1. **Overview drift:** README and roadmap foundations omitted implemented API,
   OAuth, KEV and supervised paths. Current architecture/profile summaries now
   distinguish these from the still-unimplemented domain and deployment targets.
2. **Operator-input bounds:** installed baseline `collect --config` and
   `import-text --file` blocked on a FIFO until an external subprocess timeout.
   Text import also used an unbounded `read_bytes()` before validating its length.
   Both now reuse fixed-profile regular-file admission: no-follow/nonblocking
   open, file-type and initial-size checks, bounded read and growth refusal.
   Source configuration retains its 8 MiB limit; text adds 4,000,000 bytes before
   UTF-8 decoding and the existing 1,000,000-code-point contract. Model limits and
   error codes remain unchanged. This is a local operator robustness issue;
   no source-selected/MCP file path or remote exploit was established.
3. **Standards traceability:** [six ASVS 5.0.0 controls](../security/control-evidence.md)
   now have verified identifiers, bounded source/test allocations and explicit
   partial dispositions. SSDF remains a lifecycle reference. Full applicability,
   assurance and independent verification remain open.
4. **Scope retention:** JavaScript rendering and HTML/JSON-LD are explicit backlog
   items. They require isolated, bounded execution and cannot become hidden
   parser/network fallbacks. API compatibility/authentication does not establish
   content-use rights, provider qualification or query-disclosure approval.
5. **Verification navigation:** contributor guidance points to the extracted
   same-commit installed-profile workflow, not only its matrix orchestrator.
6. **Application archive identity:** the locally built application retained an
   old `locked_wheel_sha256` entry despite having no registry candidate in
   `uv.lock`. That application-only field is removed; `reviewed_archives` retains
   the inspected local-wheel identity. Third-party locked/archive evidence is
   unchanged.

The input correction allocates to existing SC3/SC6 and C7/C45, with fixed sanitized
feedback under SC1/SC2. No new authority, endpoint, automatic model selection or
external effect is introduced. Parent directories and operator-selected regular
files remain trusted; regular-file I/O has no physical deadline. The change does
not claim a complete filesystem sandbox or whole-tick latency bound.

## Validation and recovery

Candidate acceptance requires source/Markdown/static checks; before/after FIFO
behavior; special-file, oversize, growth, exact-bound and UTF-8 tests; installed
full native suites on both LTS defaults; real systemd/credential acceptance;
hashed wheel/sdist scans; and exact producer/licence/native/signing evidence.
Optional 3.13 can be exercised independently and never substitutes for the two
required profiles. Candidate results must name their actual revision; this
pre-commit review does not invent future outcomes.

README is package METADATA. Compare actual baseline/candidate wheels before
refreshing the application's evidence hashes. Preserve third-party evidence,
shipped licence bytes, dependency lock, SQL migration bytes, schema/profile bounds
and unresolved legal outcomes. Only reviewed application bytes may be rebound.

The [actual wheel comparison](readme-alignment-wheel-2026-10-19.json) records the
baseline/candidate hashes and all changed members. Only `cli.py`, METADATA and
RECORD change; licence text and metadata headers match, and every archive member
was checked for ELF magic. This archive inspection does not establish full
native closure or replace installed/native acceptance.

Rollback is a protected source revert/rebuild of the input reader and current
documentation, accompanied by matching application-wheel evidence. No data
migration or operational deployment occurs. Reverting the guard restores the
known FIFO/unbounded-read behavior, so a forward repair is preferable if needed.
Historical receipts/publication findings remain intact. No live source, paid
provider, pretrained model download, private prototype or operational host is
modified by this review.
