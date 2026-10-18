# OSINT Workbench

A reference setup combining existing tools and custom integration code to collect,
store and search open-source information, with MCP access for AI assistants.

**Development foundation. This is not the completed reference implementation.**
The design includes local inference, embeddings, hybrid retrieval, enrichment,
graph assertions, vulnerability/regulatory intelligence and optional governed cloud
APIs. Several bounded paths are implemented; the full profiles remain incomplete.
Their implementation and verification status is tracked in
[STATUS.md](STATUS.md). Installing a small core does not satisfy the full roadmap.

## Implemented foundation

- Python package and CLI with explicit configuration and no bundled source list.
- PostgreSQL migration, reader/writer role groups, immutable document versions,
  active document heads and transactional downstream work records.
- Content-addressed evidence objects with hash checks and no-follow file access.
- Lexical full-text search and a real MCP stdio server with seven read-only tools.
- Durable job leases with fencing and stale-completion rejection.
- RSS/Atom extraction and a public-only HTTP path with DNS pinning, redirect,
  byte and absolute network deadlines. Compressed responses are rejected.
- Coordinate-preserving evidence quotation matching, embedding-space validation
  and deterministic reciprocal-rank fusion primitives.
- Local generation proposals, operator-attributed review and evidence-bound cited
  digests; a quote match does not establish entailment or independent review.
- An explicitly selected compatible cloud enrichment route with deny-by-default
  policy, conservative reservations and separately authorized operator settlement.
- Private checkpoint/restore, logical retirement, reviewed orphan GC and scoped
  SQL purge; retained accounting and external copies remain outside content erasure.

The optional retrieval profile now executes local ONNX embeddings and exact pgvector
hybrid search with versioned generations. An optional local ONNX pair reranker is also available. Pretrained semantic-quality
acceptance remains pending. See [local retrieval](docs/local-retrieval.md) and
[frozen local quality diagnostics](docs/local-quality.md).
No model/provider is selected or downloaded automatically. Local model calls need
an explicit configured profile; remote enrichment needs an explicit route, data
class, private policy and credential. There is no silent cloud fallback. No real
cloud keys or operational data are required for the test suite.

## Development

CPython 3.12–3.14 is supported. Required CI covers Ubuntu 24.04/Python 3.12 and
3.13, plus Ubuntu 26.04/Python 3.14; PostgreSQL integration targets version 18.
See [runtime support](docs/runtime-support.md) for deployment and evidence limits.

```sh
uv sync --locked --extra retrieval
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/check_repository.py
.venv/bin/python -m pytest -m 'not integration' --import-mode=importlib
uv build --build-constraints build-constraints.txt --require-hashes
```

The mandatory database/MCP suite uses an isolated database named `ow_test`:

```sh
# Set OW_TEST_ADMIN_DSN in the private local environment, never in Git.
.venv/bin/python -m pytest --require-integration --import-mode=importlib
```

The base fixture refuses any other database name. Recovery tests additionally
create and drop their own randomly named `ow_test_restore_` databases using the
disposable administrator; that identity requires database creation privileges.
Never point this suite at operational storage. CI installs the built wheel and
tests it against a disposable PostgreSQL service rather than importing a checkout.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete installed-artifact and
native dependency procedure. Do not resynchronize an environment during its
installed-wheel test run.

## Operator interfaces

`OW_MIGRATION_DSN` is used by `migrate` and `migrate-retrieval`. Provision separate
login identities inheriting only `ow_collector`, `ow_writer` or `ow_reader`, then
provide their private DSNs as `OW_COLLECTOR_DSN`, `OW_WRITER_DSN` and
`OW_READER_DSN` for those distinct processes. Collection validates its effective
SQL authority before dispatch and never falls back to writer credentials. The MCP server rejects a privileged
reader or unsafe overlapping application authority. Mount evidence read-only for
reader processes; the Python flag alone is not an OS permission boundary.

Set `OW_EVIDENCE_ROOT` to private persistent storage outside the source tree.

```sh
osint-workbench migrate
osint-workbench collect --config config/sources.example.json
osint-workbench import-text --file ./synthetic.txt --source-id fixture --title Example
osint-workbench search evidence
osint-workbench status
osint-workbench work-once
osint-workbench job inspect JOB_UUID
osint-workbench job cancel JOB_UUID
osint-workbench mcp
```

The example source configuration is empty and performs no acquisition. Supply real
source URLs in private external configuration. Importing a file is an explicit
operator action; MCP accepts document/snapshot IDs, never arbitrary paths or URLs.
Feed collection stores versioned raw feed bytes and normalized entry text. It does
not recursively fetch articles or claim full-text coverage beyond supplied entries.

`get_evidence` verifies byte integrity, not truth. Content remains untrusted, and a
remote AI client can disclose locally retrieved content to its own provider. Current
MCP transport is local stdio; authenticated remote HTTP remains unimplemented.

`work-once` validates stored evidence, produces versioned character chunks, then
commits the chunks, downstream work record and completion atomically. Repeat it
under an external supervisor; it does not start a background daemon. It claims only
job kinds it implements. Cancellation is an operator write, never an MCP tool.
See [workflow contracts](docs/workflows.md) for retry and recovery semantics.

See [local intelligence](docs/local-intelligence.md) for generation, proposal review
and cited-digest contracts. [Cloud routing and settlement](docs/cloud-routes.md)
uses explicit worker selection and a separate `OW_ACCOUNTING_DSN`; provider facts
are operator declarations, not independently verified sovereignty evidence.
Lifecycle and purge commands also require their separately scoped credentials.

See [private recovery](docs/recovery.md) for bounded consistent checkpoints and
isolated restore. Checkpoints contain private records and are not public exports.
See [lifecycle controls](docs/lifecycle.md) for operator-only retention, holds and
permanent logical retirement. Restore requires a separately trusted current policy
receipt. Reviewed orphan GC and transactional retired-record SQL purge are
implemented; [SQL purge](docs/retired-record-purge.md) has separate credentials and
irreversible effects. Shared copies, backup expiry and all-copy erasure remain open.

## Engineering and attribution

This is AI-assisted integration work. Human responsibility includes requirements,
design decisions, review, validation and operations. Existing libraries provide
database, parsing and protocol capabilities; this project does not claim original
model research or production assurance. Requirements and ADRs describe the target;
passing a subset of tests does not establish complete conformance.

See [architecture](docs/architecture.md), [design decisions](docs/adr/),
[security policy](SECURITY.md) and [contribution guide](CONTRIBUTING.md).
The [documentation map](docs/documentation-map.md) identifies current guidance,
target specifications and historical evidence; the [backlog](docs/implementation-backlog.md)
is the canonical ledger of unfinished work.

Operator-only [orphan cleanup](docs/garbage-collection.md) uses reviewed private
plans and durable intent receipts. It does not purge retained records or backups.

[Scheduled acquisition](docs/scheduled-acquisition.md) provides a durable due-only
tick and conditional RSS/Atom fetching; source configuration stays private.
