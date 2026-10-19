# Bounded test-cost review: 2026-10-19

Baseline: `87ba1730a2c43369a3e5d297ffec5d8fc5411bfd`.
This review concerns test cost and selection. It does not establish full roadmap,
semantic-quality, operational deployment or standards acceptance.

## Findings and scope

AST inspection found 717 test functions in 81 test modules and 253 parametrization
decorators. Pytest collected 1,693 cases. There is no required count or minimum.
The largest expansion is the advisory-envelope module: 47 functions produce 161
cases. Similar bodies do not by themselves establish redundant coverage.

A literal-AST check found no identical entries within explicit parameter lists.
One pair of test bodies was identical, but its data exercises different admission
constraints, including JSON Boolean versus integer values. It was retained.
Manual sampling covered advisory validation, HTTP framing/retry propagation,
credentials, chunk operations, native generation and process/concurrency guards.
This is not a semantic redundancy proof for every case. Cases can be consolidated
when their independent detection purpose is shown to remain covered.

The last completed baseline main job's step times were:

| Ubuntu 24.04/Python 3.12 step | Elapsed |
| --- | --- |
| Compile pinned native CPU dependency | 281 s |
| Install and test the built wheel | 403 s |
| Generate and verify build evidence | 22 s |

Source: [job 118205066533](https://github.com/rmednitzer/osint-workbench/actions/runs/39294992952/job/118205066533).
Both baseline LTS profiles passed all 1,693 cases. The test step also includes
creating/installing the environment; it is not pure test execution time.
Compilation is a substantial separate cost, not a reason to delete regressions.

## Bounded changes

Four test modules started HTTP/Unix fixture servers with the standard 500 ms
shutdown poll. Select a 50 ms poll while preserving request/deadline behavior,
failure injection, shutdown/join bounds and test cases. No production server
polling or meaningful timeout wait changes.

Every CLI invocation also eagerly imported the MCP SDK. Import the stdio server
only in the `mcp` command. Help output is unchanged; non-MCP commands do not need
that import. Real MCP protocol/SQL cases remain required. No dependency becomes
optional, and no model/data route or authority changes.

The required verifier prints pytest's 25 slowest phases above 100 ms. No new test
framework, artifact format, quota or performance gate is introduced. Both full LTS
profiles, separate core installation, publication checks and main signing remain.
No cache of unverified compiled code or parallel shared-database execution is added.

## Local diagnostic

A dedicated CPython 3.12 installed-wheel environment used the unchanged locked
retrieval/development dependencies. The unchanged baseline non-integration run
reported 1,271 passes, 31 database-dependent skips, 389 deselections and two
parent-lifetime failures in this tool environment (137.46 s). These failures and
missing database coverage are not a passing local full-suite result. Baseline
native main acceptance above and current candidate CI are separate evidence.

The same 70 local API cases passed before and after the fixture/import changes:
21.31 s and 8.04 s respectively. These are single sequential diagnostic runs,
not a capacity benchmark or CI-speed guarantee. Pytest node-ID comparison checks
that all 1,693 collected cases remain identical; actual required native results
belong to the exact PR/main runs, not this diagnostic.

## Selection and reversibility

[Proportional test design](../../CONTRIBUTING.md#proportional-test-design) is the
shared contributor/agent policy. Prefer a discriminating regression over many
variants of the same fact; keep native tests for properties units cannot prove.
Ordinary fixture tuning needs relevant existing checks, not a new ADR or tests
that merely mirror the changed lines. Existing runtime/support decisions remain.

Rollback is a normal protected revert of fixture polling, deferred MCP import and
timing output. There are no data/schema/grant changes or operational deployment
steps. Historical receipts and test counts retain their original revisions.
