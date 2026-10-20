# Contributing

Read [AGENTS.md](AGENTS.md) and [STATUS.md](STATUS.md). Keep changes bounded,
preserve the roadmap and explain behavior, relevant failure paths and recovery.
Use synthetic fixtures; do not commit private source lists, acquisition URLs,
credentials, identifiers, prompts or operational/model/provider responses.

## Development checks

The minimum is CPython 3.12. Required full native CI covers 24.04/3.12 and
26.04/3.14. Optional weekly/manual 3.13 compatibility and manual 3.15 dependency
probes are separate from merge/signing requirements; see
[runtime support](docs/runtime-support.md).
The commands below use 3.12; reproduce the relevant CI profile with its interpreter.
PostgreSQL integration targets PostgreSQL 18 with pgvector. Use the uv version
pinned in the workflow when reproducing CI.

```sh
uv sync --locked --extra retrieval --python 3.12
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/check_repository.py
.venv/bin/python scripts/check_static.py
.venv/bin/python -m pytest -m 'not integration' --import-mode=importlib
uv build --python 3.12 --build-constraints build-constraints.txt --require-hashes
.venv/bin/python scripts/check_publication.py --artifacts dist
```

The checkout suite is a development check, not installed-artifact acceptance.
Existing interpreters are preferable for review. Do not synchronize/install into
another task's active environment; `uv run` can silently replace an installed wheel
with the editable checkout. Record unavailable integration separately from passes.

## Proportional test design

Choose tests by the independent fault they detect and the consequence of missing
it. There is no required test count, per-change test quota or coverage-percentage
target. A case count is an observation of a revision, not evidence of completeness.
Use the requirements, actual trust boundaries and known defects to select cases.

Keep cheap input partitions in parameterized unit tests. Use native transport,
SQL, process and installed-CLI cases for behavior those unit tests cannot prove:
authorization, framing, transactional acceptance, concurrency, deadlines, crash
recovery and packaging. Similar assertion bodies can be necessary when their
inputs distinguish different hazards; function-count reduction alone is not a
simplification. Avoid Cartesian products of independent options without a named
interaction to detect. Consolidate cases when their failure-detection purpose is
duplicated and remains covered at the appropriate layer.

For a fix, add a regression only when existing coverage does not distinguish the
fault. Documentation, comments and reversible low-impact fixture changes normally
need relevant existing checks rather than new tests. Material architecture changes
need an ADR; ordinary test maintenance does not require a new decision record.
Do not shorten meaningful timeout/crash waits or replace actual integration with
mock success to improve timing. Optimize setup, cleanup and unnecessary imports
before removing useful boundary coverage.

For development, run the affected cases first. Use `--durations=25
--durations-min=0.1` to find expensive calls/setup/teardown; these observations are
not a performance SLO. Full installed/native acceptance on both required LTS
profiles remains the merge/signing contract. PostgreSQL fixtures share database
state: do not enable parallel pytest workers without isolated databases and
independent lifecycle/admission resources. See the bounded
[2026-10-19 cost review](docs/testing/test-cost-review-2026-10-19.md).

## Verify the installed wheel

Use a dedicated environment and actual locked dependencies. These commands do not
download models or call providers, but dependency installation can use registries.

```sh
ow_verify_dir=$(mktemp -d /tmp/ow-verify.XXXXXX)
uv venv "$ow_verify_dir" --python 3.12
uv export --locked --extra retrieval --no-emit-project --output-file "$ow_verify_dir/requirements.txt" > /dev/null
uv pip sync --python "$ow_verify_dir/bin/python" --require-hashes "$ow_verify_dir/requirements.txt"
uv pip install --python "$ow_verify_dir/bin/python" --no-deps dist/*.whl
"$ow_verify_dir/bin/python" -c 'import osint_workbench; assert "site-packages" in osint_workbench.__file__'
"$ow_verify_dir/bin/python" -m pytest -m 'not integration' --import-mode=importlib
```

Keep this environment unchanged until verification ends. Identify wheel/sdist and
uv.lock with SHA-256. Public commits may use an explicit automation author with a
reserved `.invalid` email. Select an intentional Git identity before committing;
do not rewrite public history without authorization.

## Full native integration

The required gate is orchestrated by [.github/workflows/ci.yml](.github/workflows/ci.yml)
and executes the same-commit [installed-profile workflow](.github/workflows/installed-profile.yml).
It explicitly prepares source with `scripts/prepare_native.py`, verifies its
archive digest, and builds the native CPU server with the exact flags in CI.
This separate preparation requires network access; package imports and tests do
not fetch it implicitly. Reuse a verified owned build by setting
`OW_TEST_LLAMA_BIN` to its `llama-server` executable.

Set `OW_TEST_ADMIN_DSN` privately to an isolated disposable database named
`ow_test`. Its fixture administrator must be able to create/drop the randomly
named `ow_test_restore_` databases owned by the recovery harness. Never use an
operational database, data volume or fleet runner.

```sh
# OW_TEST_ADMIN_DSN and OW_TEST_LLAMA_BIN must already name disposable fixtures.
OW_TEST_RETRIEVAL=1 "$ow_verify_dir/bin/python" -m pytest --require-integration --import-mode=importlib
```

Missing mandatory native dependencies are not passes. ONNX/GGUF fixtures establish
execution contracts, not pretrained quality. GPU, real provider, operational
recovery and independent semantic acceptance need separate explicit evidence.
Do not run the privileged reference-service harness on an ordinary host: its
guarded manual workflow requires an explicitly selected disposable GitHub runner.

## Repository and dependency checks

`scripts/check_repository.py` checks tracked and new nonignored local Markdown links/headings, agent
bridges and immutable action/image references. It also compares STATUS's explicit
current schema/profile/checkpoint versions with source declarations, and its
ADR/requirement/scenario counts with the actual numbered registers. This uses
standard-library AST parsing without importing application dependencies; historical
receipt counts remain independent. It does not validate external link
availability, prose truth, every Markdown construct or full workflow semantics.
The [maintenance policy](docs/repository-maintenance.md) defines Renovate,
advisory auditing, coupled build updates and observed-setting verification.

The standalone Renovate validator must run in repository mode:
`renovate-config-validator --strict --no-global renovate.json`. This checks shape
and migrations but does not establish that presets resolve. Run
`bash scripts/check_renovate.sh` from the repository root to reproduce CI's pinned
container checks: schema validation, actual offline preset resolution/dependency
extraction, and a known invalid-preset negative control. Docker image preparation
requires registry access; all three validation runs have no network or credentials.
Local Node/npm installations are separate from the Python environment and are
not runtime dependencies.

Run publication checks on source and artifacts. Maintainers may set
`OW_PRIVATE_DENYLIST` to an external private JSON array for additional exact-value
checks; never commit or upload that file. Scan new Git metadata with an explicit
reviewed ancestor; see [publication privacy](docs/publication-privacy.md).
Scans are backstops, not permission to disclose arbitrary material.

## Bounded static analysis

Run `.venv/bin/python scripts/check_static.py` after the locked development
installation. It runs mypy on the advisory wire models, configuration/document
contracts, sanitized errors and evidence text/coordinate helpers. It checks
untyped function bodies as well as annotated signatures, without claiming strict
typing or eliminating `Any`. Imported modules are analyzed silently; they are
not part of the reported four-module gate. The minimum language target remains
Python 3.12, independently of the native runtime matrix.

The same command runs every Ruff `S` security rule against application Python
source under `src/osint_workbench`. Exact line-level exemptions document reviewed
heuristics: the fixed-interpreter parser subprocess, the descriptor-anchored
inference lock protocol's intentional `/tmp` default, and SQL fragments selected
only from internal constants in retrieval and cloud accounting. Review the
adjacent rationale when changing any exempted operation; do not broaden its
inputs. There are no file-wide security exemptions. The predictable
lock still assumes a trusted service account; static analysis does not establish
filesystem isolation, safe subprocess inputs or SQL authority by itself.

Every invocation also runs two disposable negative controls through the actual
tools: an incorrect assignment inside an untyped function must fail mypy, and
an unsafe dynamic-evaluation call must fail Ruff. A missing tool, failed gate or
unexpected control result fails the command. No gate downloads packages, invokes
providers or executes the negative fixture code. Scripts, tests, SQL migrations,
external/native code and dependency vulnerabilities are outside this source
security-rule gate; installed native tests, publication scans and dependency
auditing remain separate checks. Broader type coverage and independent security
review remain unfinished.

After successful installed tests and package scans, reproduce the dedicated
runtime-inventory environment, CycloneDX generation and exact licence evidence
verification in [build evidence](docs/build-evidence.md). Review dependency updates
against [the licence policy](docs/security/dependency-licences.md); changed versions
or evidence hashes must fail until their actual wheel texts are reviewed.
The [native policy](docs/security/native-components.md) also requires review of
the complete recorded ELF file set and bytes for supported standard ABIs.
Verify [supplementary notices](docs/security/supplementary-notices.md) independently;
the two upstream texts do not establish complete native notices or source
compliance. Do not copy new hashes merely to obtain green CI. CI retains the tested
distributions, receipts and four supplementary files for 30 days. Main-push signing
runs separately with no repository code execution; PR artifacts remain unsigned.

## Review and merge

Use the [PR template](.github/pull_request_template.md). Require current
`repository-policy`, `renovate-policy`, `installed-artifact` and `acceptance` checks before merge.
The `installed-artifact` aggregate requires every native matrix leg to succeed.
Use merge commits to retain tested source SHAs and their evidence ancestry. A solo
maintainer does not need a fictitious second-person approval, but remains
responsible for reviewing code, dependencies and failure evidence. Do not bypass
protection or weaken checks when they fail.

Update current runbooks and STATUS for behavior changes. Preserve historical ADR
scope and receipts, adding explicit successor notes. Requirements and full target
acceptance scenarios remain open until their complete evidence exists. Follow
the branch lifecycle in AGENTS.md and verify remote merge/post-merge outcomes.
