# ADR-0018: Bounded local CPU retrieval before a serving platform

Status: ACCEPTED for the reference subset. Date: 2026-10-17.

## Context and criteria

The complete profile still requires embeddings, hybrid/rerank retrieval, local model
serving, quality acceptance and recovery. The first executable increment needs actual
local inference, portable artifact identity, original-text coordinates, limited resource
use and native database evidence without copying private deployment or model choices.
No incremental design may hide the remaining acceptance work.

## Alternatives, including no change

- Keep lexical-only operation: least dependency/resource impact; fails embedding intent.
- Install a full model server: better warm throughput and generation reuse; introduces
  runtime ownership and endpoint authority before those contracts have been tested.
- Start with bounded local ONNX execution and exact pgvector generations: portable
  files, no provider, explicit failure and exact ranking oracle; repeated process/model
  startup and exhaustive scans limit performance.

## Decision and tie-breaker

Use the third option as an optional reference subset. Local-only supplied files are
hash-verified; no download/custom model code/network endpoint is configured. Token-aware
splits recheck complete input budgets. Default CPU slot admission is process-shared;
queries fail busy instead of oversubscribing. Exact scans provide the verification
baseline for later ANN recall tests. Build readiness and activation are distinct.
A declared, bounded implementation with testable numerical behavior wins over an
unmeasured serving/ANN stack. This does not close the complete profile requirement.

## Consequences and authority

Operators approve/mirror model and native dependency supply chains. Microsoft-origin
ONNX Runtime and foreign upstream/distribution dependencies remain disclosed sovereignty
constraints; local execution alone is no EU-control assurance. The profile supports
cosine/normalized float32 only. It rejects unsupported contracts and oversized corpora.
CPU tests do not support GPU or pretrained semantic-quality claims. Query/document
operations use the same space identity but distinct configured templates. No cloud
keys, paid calls or original deployment changes occur.

## Blast radius and rollback

Only opt-in retrieval schema/extra, local supplied files and explicit operator index
commands are affected. Core stays lexical when the manifest is absent. A broken
configured profile fails visibly rather than silently changing semantics. Activate a
prior ready generation only if its model identity and current corpus still match.
Remove the manifest from reader configuration to use lexical operation. Preserve the
optional schema and immutable history; no automatic destructive downgrade is supplied.

## Evidence and remaining work

`tests/test_encoder.py` uses real ONNX CPU execution with synthetic vectors.
`tests/test_vector_index.py` tests native pgvector and MCP transport, failed-build
isolation, identity mismatch, switching, rollback and corpus drift. Semantic quality,
ANN, reranking, caches, background backfill/resumption, GPU/generation serving and
complete recovery remain required. See STATUS.md and docs/local-retrieval.md.
> Implementation follow-up (2026-10-17): [ADR-0019](0019-proposals-and-local-generation.md) implements bounded native local pair scoring. Persistent caches, ANN, automatic backfill and pretrained semantic acceptance remain open; pending statements in the original record retain this ADR's original increment scope.
