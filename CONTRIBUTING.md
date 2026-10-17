# Contributing

Read [AGENTS.md](AGENTS.md) and [STATUS.md](STATUS.md). Keep changes bounded,
preserve the roadmap and explain behavior, relevant failure paths and recovery.
Use synthetic fixtures; do not commit private source lists, acquisition URLs,
credentials, identifiers, prompts or operational/model/provider responses.

## Development checks

Python 3.12 is the primary tested runtime; package bounds also permit 3.13.
PostgreSQL integration targets PostgreSQL 18 with pgvector. Use the uv version
pinned in the workflow when reproducing CI.

```sh
uv sync --locked --extra retrieval --python 3.12
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/check_repository.py
.venv/bin/python -m pytest -m 'not integration' --import-mode=importlib
uv build --build-constraints build-constraints.txt --require-hashes
.venv/bin/python scripts/check_publication.py --artifacts dist
```

The checkout suite is a development check, not installed-artifact acceptance.
Existing interpreters are preferable for review. Do not synchronize/install into
another task's active environment; `uv run` can silently replace an installed wheel
with the editable checkout. Record unavailable integration separately from passes.

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

The full gate is implemented in [.github/workflows/ci.yml](.github/workflows/ci.yml).
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

`scripts/check_repository.py` checks tracked local Markdown links/headings, agent
bridges and immutable action references. It does not validate external link
availability, prose truth, every Markdown construct or full workflow semantics.
The [maintenance policy](docs/repository-maintenance.md) defines Renovate,
advisory auditing, coupled build updates and observed-setting verification.

The standalone Renovate validator must run in repository mode:
`renovate-config-validator --strict --no-global renovate.json`. CI uses a
digest-pinned official container; local tool installation is separate from the
Python environment. Node/npm installations are not runtime dependencies.

Run publication checks on source and artifacts. Maintainers may set
`OW_PRIVATE_DENYLIST` to an external private JSON array for additional exact-value
checks; never commit or upload that file. Check Git metadata independently.
Scans are backstops, not permission to disclose arbitrary material.

## Review and merge

Use the [PR template](.github/pull_request_template.md). Require current
`repository-policy`, `renovate-policy` and `installed-artifact` checks before merge.
Use merge commits to retain tested source SHAs and their evidence ancestry. A solo
maintainer does not need a fictitious second-person approval, but remains
responsible for reviewing code, dependencies and failure evidence. Do not bypass
protection or weaken checks when they fail.

Update current runbooks and STATUS for behavior changes. Preserve historical ADR
scope and receipts, adding explicit successor notes. Requirements and full target
acceptance scenarios remain open until their complete evidence exists. Follow
the branch lifecycle in AGENTS.md and verify remote merge/post-merge outcomes.
