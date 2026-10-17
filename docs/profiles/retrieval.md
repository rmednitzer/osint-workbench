> Target specification. See STATUS.md for implemented and verified scope.

# Retrieval and local embedding/reranking specification

Scope: C04-C06, with C12/C13 resource integration. All specified behaviours are implementation requirements, not verified prototype properties.

## Chunk and embedding identity

Snapshot-normalized text is immutable. Chunk manifests include extractor and normalization versions, tokenizer revision, section boundaries, chunk token budget/overlap, document/snapshot/chunk IDs, start/end coordinate mapping and actual token count. Preserve structured article/chapter/annex context. Reject silent input truncation; oversized content is chunked deterministically or explicitly partial. A new chunking strategy creates a new generation, not an in-place mutation.

An embedding space fingerprint includes model artifact/revision, tokenizer, query/document instruction templates, pooling, normalization, dimensions, precision and distance metric. A vector is identified by chunk-content hash plus that fingerprint. Validate shape, numeric type, finite values and expected norm policy at write/query boundaries. Equal dimensions alone do not establish compatible spaces. Reject query/index mismatches before searching; do not silently resize/truncate vectors.

Use a registry-driven local encoder contract with embedding_documents and embedding_queries separately declared. Select one tested CPU-capable reference model; support additional spaces through the same interface. Runtime acquisition of model code/weights is disabled. A local inference/generation API claiming embeddings is usable only after its exact embedding contract is tested; generation compatibility is insufficient.

## Index and search

Use PostgreSQL FTS/exact identifier matching and pgvector exact search as the initial correctness oracle. Add HNSW/other ANN indexes only after filtering, recall and update behaviour is benchmarked against exact search. pgvector documents post-index filtering effects [S7](../references.md#s7); authorisation/source/workspace filtering and query plan choice must not silently drop all relevant candidates. Isolate incompatible spaces and prevent cross-workspace leakage before fusion/rerank/graph expansion.

One application query API supports lexical, vector and hybrid strategies. Apply deterministic reciprocal-rank fusion with documented rank convention and tie-breakers; do not compare raw scores from unrelated models. Optional multi-encoder fusion is supported by configuration and evaluated against one-encoder/no-change alternatives. Return strategy, contributing ranks, generation, snapshot IDs and degradation reasons. Graph expansion returns separately attributed context; it cannot change an unsupported graph edge into evidence.

Rerank a bounded authorized candidate set only. Validate output cardinality, unique candidate identity, finite score and order. Reject extra/missing IDs as invalid. Cache keys include normalized query, candidate IDs/content hashes, filters/workspace, model/prompt revision and corpus generation. Bound TTL, memory and in-flight coalescing; waiter timeout cannot cancel the shared owner incorrectly or leak a result from another profile.

## Lifecycle and degradation

Index jobs are durable and idempotent. Backfill a new embedding generation beside the active one; verify coverage/dimensions/quality before an atomic alias switch. Old generations remain readable for rollback until explicit retention policy permits removal. Model reload, prompt/template changes, deletion/tombstones and workspace authorization changes invalidate dependent caches/indexes. Report missing/stale/failed vectors separately from source absence.

Local embed/rerank outages may fall back to lexical retrieval if the requested policy permits and the response labels it degraded. They must never route to cloud implicitly. A reranker failure preserves authorized candidates; it must not convert a failed retrieval into a successful empty result.

## Quality and acceptance

Freeze a retrieval dataset before model selection with at least exact identifiers, paraphrases, long sections, English/German text, negation, duplicate/syndicated stories, stale versions and domain terminology. Keep selection/development and held-out evaluation sets distinct. Human-authored relevance labels and exact expected identifiers are primary oracles; LLM-as-judge is supplementary and identified.

Measure Recall@k, nDCG@k, exact-identifier recall, filtered recall versus exact search, latency percentiles under declared load, memory, queue time, cache correctness and failure/abstention. Proposed initial quality contract: every critical exact-identifier/authorization/evidence case passes; hybrid quality on the frozen aggregate is at least the lexical baseline within a predeclared comparison method, and reranking cannot regress the critical subset. The maintainer must accept numerical per-language/domain targets and regression tolerance at M0 before candidate evaluation. Unset targets block a semantic-quality claim, not hide a failing model.

E21-E24 and E34-E36 use real local model computation. Protocol mocks alone do not qualify. Report tested model/quantization/hardware identities without publishing the original private inventory. No universal model/hardware performance claim follows.
