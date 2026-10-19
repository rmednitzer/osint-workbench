# OSINT Workbench

A self-hostable integration workbench for collecting, preserving and searching
open-source information, with a read-only MCP interface for AI assistants.
It combines a Python application, PostgreSQL, immutable evidence storage and
optional local inference or explicitly governed cloud enrichment.

**Development status:** collection, evidence reads, local retrieval, enrichment,
recovery and supervised service paths are implemented within documented bounds.
The complete reference platform remains unfinished. [STATUS.md](STATUS.md)
separates implemented behavior, revision-bound verification and remaining
acceptance; [the roadmap](ROADMAP.md) and [backlog](docs/implementation-backlog.md)
retain the full intended scope.

## What works today

| Capability | Implemented scope | Important boundary |
| --- | --- | --- |
| Acquisition | Scheduled RSS/Atom, bounded JSON-page APIs, a KEV-format catalogue adapter and bearer/API-key or OAuth client-credentials authentication | Endpoints and credentials are supplied externally. Restricted licensed content, paid queries, general article/PDF extraction and JavaScript rendering remain open. |
| Evidence and jobs | Immutable raw/normalized versions, current document heads, content-addressed objects, integrity checks and leased/fenced work | The generic worker processes `document.accepted`; unsupported downstream job kinds remain queued. |
| Search | PostgreSQL lexical search; optional local ONNX embeddings, token-aware retrieval chunks, exact pgvector/RRF hybrid search and pair reranking | Models require explicit manifests and local artifacts. Pretrained usefulness, independent relevance/abstention acceptance, ANN and large-corpus operation remain open. |
| Enrichment and cited products | Native local generation, an opt-in [local chat API](docs/local-inference-api.md) or an explicit cloud extraction route, typed assertion proposals, original-text quotations, append-only operator review and cited digests | A matching quote does not establish entailment. Review actors are attribution; independent reviewer authentication, richer entity resolution and analytical briefings remain open. |
| Cloud governance | Deny-by-default route/data policy, per-currency reservations, uncertain-outcome tracking and separately authorized operator settlement | Provider facts are declarations. Native vendor adapters, streaming, batches, invoice reconciliation and live-provider/sovereignty acceptance remain open. |
| Lifecycle and recovery | Retention, holds, logical retirement, private checkpoint/isolated restore, reviewed orphan GC and scoped SQL purge | Full-host/PITR recovery, backup expiry and all-copy erasure remain open; accounting and external copies have separate retention. |
| Services and health | Non-root systemd templates for feed/API collection, bounded chunk-worker ticks and aggregate health | Deployment needs explicit accounts, storage, secrets and thresholds. Complete stack provisioning, monitoring/alert delivery and operational acceptance remain open. |
| Assistant access | Seven bounded read-only MCP tools over local stdio, including configured local search inference | No acquisition, generation, job-control, arbitrary SQL/path/URL or host-administration tools. Authenticated remote MCP and independent assistant-client acceptance remain open. |

The vulnerability profile currently provides an offline advisory-observation
contract and KEV-format document ingestion. A complete applicability/prioritization
engine and regulatory-intelligence profile remain roadmap work. Source claims,
catalogue membership and model output do not establish target exposure or legal
applicability.

## Start with the core

Native Ubuntu installation uses the distro Python in a virtual environment:
Ubuntu 24.04/Python 3.12 or Ubuntu 26.04/Python 3.14. See
[runtime support](docs/runtime-support.md#native-ubuntu-installation) for package
prerequisites. From a checkout, this core smoke check needs no database, model,
cloud account or configured sources:

```sh
uv sync --locked --no-dev --python /usr/bin/python3
.venv/bin/osint-workbench collect --config config/sources.example.json
```

Expected output: `{"status": "unconfigured", "sources": 0}`. Dependency installation
uses the configured package registry; this command performs no source acquisition.
The bundled source list is empty. Keep real source URLs, credentials, prompts,
private inventories and deployment configuration outside Git and public CI.

For a working database-backed installation, follow [deployment](docs/deployment.md)
and the [supervised profile](docs/operational-profile.md). Provision PostgreSQL 18,
separate migration/collector/writer/reader identities and persistent evidence
storage before running migrations or workers. Optional hybrid retrieval adds
pgvector and the `retrieval` dependency extra; it also needs explicitly selected
model artifacts, manifests and an activated compatible index generation.

No model or provider is selected or downloaded automatically. Remote enrichment
requires an explicit route, data class, private policy and credential. There is
no silent cloud fallback. An MCP client can disclose returned content to its own
provider, even when this application runs locally. A verified hash establishes
byte integrity; retrieved content remains untrusted.

## Operator workflows

| Task | Procedure |
| --- | --- |
| Schedule feeds or authenticated APIs | [Feed acquisition](docs/scheduled-acquisition.md), [API acquisition and secret custody](docs/api-acquisition.md), [OAuth](docs/oauth-acquisition.md), [KEV format](docs/kev-acquisition.md) |
| Process supported jobs and inspect failures | [Workflow contracts](docs/workflows.md) and [supervised processing/health](docs/operational-profile.md) |
| Configure embeddings, hybrid retrieval or reranking | [Local retrieval](docs/local-retrieval.md) and [quality diagnostics](docs/local-quality.md) |
| Generate, review and read cited products | [Local intelligence](docs/local-intelligence.md), [local API](docs/local-inference-api.md) and [cloud routes/accounting](docs/cloud-routes.md) |
| Retire data, recover or remove retained objects/rows | [Lifecycle](docs/lifecycle.md), [private recovery](docs/recovery.md), [orphan GC](docs/garbage-collection.md), [SQL purge](docs/retired-record-purge.md) |
| Connect an assistant | [MCP read contract](docs/mcp-read-contract.md) |

Use only the credentials needed by each process. Collection never falls back to
writer credentials; the MCP server rejects broader reader authority. Enforce
read-only evidence access at the OS/mount boundary as well as in Python. Recovery,
lifecycle, purge and accounting have separately scoped credentials and effects.
Private checkpoints are not consumer exports.

Operator configuration/import paths must name regular files, with no final
symlink. Feed configuration is capped at 8 MiB; text import is capped at
4,000,000 UTF-8 bytes and 1,000,000 Unicode code points. See the
[file-admission boundary](docs/security/secure-development.md#threat-boundary-review).

## Development and verification

CPython 3.12–3.14 is permitted. Required installed/native CI qualifies
Ubuntu 24.04/Python 3.12 and Ubuntu 26.04/Python 3.14. Python 3.13 has separate
optional weekly/manual coverage; Python 3.15 has a manual dependency-only probe
and remains outside the package bound. Neither optional profile gates merges or
main-build signing.

```sh
uv sync --locked --extra retrieval --python /usr/bin/python3
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/check_repository.py
.venv/bin/python scripts/check_static.py
.venv/bin/python -m pytest -m 'not integration' --import-mode=importlib
uv build --python /usr/bin/python3 --build-constraints build-constraints.txt --require-hashes
.venv/bin/python scripts/check_publication.py --artifacts dist
```

These checkout checks are development feedback. CI installs the built wheel into
a separate environment and requires the full native suite against disposable
PostgreSQL/pgvector, HTTP/TLS/Unix transports and synthetic ONNX/GGUF fixtures.
[CONTRIBUTING.md](CONTRIBUTING.md) documents the exact procedure, pinned native
dependency and `--require-integration` gate. Its database fixture must be named
`ow_test`; recovery tests create/drop their own `ow_test_restore_` databases.
Never use operational storage or resynchronize an installed-wheel test environment.
Separate disposable service tests validate systemd and credential isolation.

Synthetic execution tests establish bounded contracts. They do not establish
pretrained semantic quality, representative capacity, GPU support, actual-provider
behavior, full-host recovery or complete acceptance of all 51 roadmap scenarios.
Current results must identify their tested source and artifact. See
[STATUS.md](STATUS.md), [the verification programme](docs/testing/verification-plan.md)
and [the alignment review](docs/testing/roadmap-alignment-2026-10-19.md).

## Engineering and attribution

This is AI-assisted integration work. Human responsibility includes requirements,
design decisions, review, validation and operations. Existing libraries supply
database, parsing, model-runtime and protocol capabilities; this project does not
claim original model research or production assurance.

The engineering baseline uses ADRs, STPA-derived constraints, explicit trust
boundaries, least privilege, bounded work, failure/recovery tests, locked builds
and publication review. NIST SSDF and selected OWASP ASVS controls are engineering
references; [the control evidence](docs/security/control-evidence.md) records
bounded coverage and gaps, without a certification or regulatory-conformance claim.
Signed main-build evidence binds tested bytes and workflow identity; it does not
establish vulnerability freedom or complete redistribution clearance.

Read [AGENTS.md](AGENTS.md), [architecture](docs/architecture.md),
[decisions](docs/adr/), [the security policy](SECURITY.md) and
[secure development](docs/security/secure-development.md) for the governing
contracts. [The documentation map](docs/documentation-map.md) distinguishes
current procedures, target specifications and historical evidence.
