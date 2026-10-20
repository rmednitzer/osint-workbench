# Capability roadmap

The goal is a self-hostable, source-configurable workbench for evidence collection,
preservation, qualified enrichment and retrieval through scoped MCP reads. The
complete programme remains in scope; a small core or a large test count does not
establish full acceptance. [STATUS](STATUS.md) describes bounded current code.
[The backlog](docs/implementation-backlog.md) owns unfinished work and closure
evidence; this page groups delivery scope rather than duplicating that ledger.

| Delivery group | Existing foundation | Remaining direction |
| --- | --- | --- |
| Acquisition, evidence and workflows | RSS/Atom, bounded authenticated JSON pages, OAuth client credentials, KEV-format catalogue ingestion, immutable versions, leased/fenced workers and due scheduling | Broader adapters/extraction including isolated JavaScript rendering, restricted-content rights, provider qualification, deployment/scale and richer failure/completeness contracts |
| Retrieval | Local ONNX embeddings, token-aware retrieval chunks, exact pgvector/RRF, pair reranking, explicit exclusions and generation activation | Independent pretrained quality, resumable/incremental backfill, persistent scoped caches and optional ANN with an exact oracle |
| Local inference and resource operation | Synthetic native generation/encoding/reranking, explicit local chat API integration and cooperative shared admission | Adopted licensed models, complete resource/fairness/termination contracts, acceleration profiles and representative measurements |
| Enrichment, graph, context and cited products | Typed proposals, evidence spans, operator-attributed review and cited digests | Independent reviewer authority and label-specific spans, aliases/merges, context lifecycle, independent support/abstention and source-diversity evaluation |
| Vulnerability and regulatory intelligence | Strict offline advisory-observation envelope, KEV-format documents, evidence-verified operator projection and domain specifications | Broader persisted observation integration, wider upstream persistence, applicability/range semantics, qualified regulatory instruments/procedures and revision transitions |
| Optional cloud and accounting | Explicit compatible enrichment route, policy denials, reservations, unknown exposure and separate immutable operator settlement | Native vendor capabilities, streaming, separate dispatcher, invoice reconciliation, correction and batch workflows; live provider/sovereignty evidence |
| MCP and authorization | Seven typed read-only stdio tools | Authenticated remote transport, scoped sessions and observed independent client compatibility |
| Operations, recovery and publication | Private checkpoint/restore, lifecycle controls, orphan GC, SQL purge, non-root feed/API/chunk/health service templates and bounded build/publication evidence | All-copy erasure/backup expiry, full-host recovery, complete deployment/observability, selected consumer export and generation-bound publishing |

Establish lifecycle, recovery and permission boundaries before adding dependent
effects. Generic parsing/domain contracts and independent quality design can
advance separately. New remote/publishing paths must retain explicit release,
budget, disclosure and reconciliation prerequisites. Preserve the useful feature
intent of the prototype while correcting its failure modes; never import private
catalogues, units, prompts or operational history as public fixtures.

Use [the documentation map](docs/documentation-map.md) to distinguish targets,
current procedures, decisions and historical evidence. Each increment needs
reviewable code/configuration changes, relevant ADR/STPA allocation, tests that
discriminate consequential failures, and source/artifact-bound results. Remaining
profiles cannot be dropped merely to claim completion.

The [2026-10-19 alignment review](docs/testing/roadmap-alignment-2026-10-19.md)
accounts for every current requirement and full acceptance scenario. It records
bounded code/test coverage and open work, without promoting regression passes to
full-profile acceptance.
