# OSINT Workbench

A reference setup combining existing tools and custom integration code to collect,
store and search open-source information, with MCP access for AI assistants.

**Development foundation. This is not the completed reference implementation.**
The full design includes local inference, embeddings, hybrid retrieval, enrichment,
graph assertions, vulnerability/regulatory intelligence and optional governed cloud
APIs. Their implementation and verification status is tracked in
[STATUS.md](STATUS.md). Installing a small core does not satisfy the full roadmap.

## Implemented in this increment

- Python package and CLI with explicit configuration and no bundled source list.
- PostgreSQL migration, reader/writer role groups, immutable document versions,
  active document heads and transactional downstream work records.
- Content-addressed evidence objects with hash checks and no-follow file access.
- Lexical full-text search and a real MCP stdio server with five read-only tools.
- Durable job leases with fencing and stale-completion rejection.
- RSS/Atom extraction and a public-only HTTP path with DNS pinning, redirect,
  byte and absolute network deadlines. Compressed responses are rejected.
- Coordinate-preserving evidence quotation matching, embedding-space validation
  and deterministic reciprocal-rank fusion primitives.

The retrieval primitives are **not** a working embedding/index/reranking profile.
No model/provider is selected, downloaded or called automatically. No cloud keys
or operational data are required by the current code or tests.

## Development

Python 3.12 is the primary tested runtime. PostgreSQL integration targets version 18.

```sh
uv sync --locked
uv run ruff check .
uv run pytest -m 'not integration'
uv build
```

The mandatory database/MCP suite uses an isolated database named `ow_test`:

```sh
# Set OW_TEST_ADMIN_DSN in the private local environment, never in Git.
uv run pytest --require-integration
```

Tests refuse any other database name and truncate only the test schema's tables.
Do not point this suite at operational storage. CI installs the built wheel and
tests it against a disposable PostgreSQL service rather than importing a checkout.

## Operator interfaces

`OW_MIGRATION_DSN` is used only by `osint-workbench migrate`. Provision separate
login identities inheriting `ow_writer` and `ow_reader`, then provide their private
DSNs as `OW_WRITER_DSN` and `OW_READER_DSN`. The MCP server rejects a privileged
reader or one that also belongs to the writer role. Mount evidence read-only for
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

## Engineering and attribution

This is AI-assisted integration work. Human responsibility includes requirements,
design decisions, review, validation and operations. Existing libraries provide
database, parsing and protocol capabilities; this project does not claim original
model research or production assurance. Requirements and ADRs describe the target;
passing a subset of tests does not establish complete conformance.

See [architecture](docs/architecture.md), [design decisions](docs/adr/),
[security policy](SECURITY.md) and [contribution guide](CONTRIBUTING.md).
