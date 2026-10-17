# ADR-0005: Include hybrid retrieval and model lifecycle as a complete profile

Status: PROPOSED, revision 2. Owner: maintainer. Date: 2026-10-17.

## Context
Lexical retrieval is a useful oracle/fallback but omitting embeddings/reranking would fail the intended complete setup.

## Alternatives and no change
Lexical only; copy the existing ML stack; cloud-only retrieval; or a model-registry-driven local hybrid profile. No change means keep the prototype private; prefer that over unsafe publication.

## Decision and tie-breaker
Implement chunking, embedding spaces, pgvector exact/ANN search, deterministic fusion, reranking, scoped caches, backfill, generation activation and labelled lexical degradation. One tested reference model per role is enough initially; model identities/dimensions are configured, never hardcoded. Prefer the smallest architecture satisfying the complete capability and authority contracts, not the fewest features.

## Consequences and blast radius
Adds model/runtime quality and resource testing. ML remains optional to install but not omitted from delivery. Filtered ANN and multi-model paths need independent recall oracles. Scope is the extracted project; no original deployment changes.

## Reversibility
Keep lexical operation while restoring previous model/index generation. Change models by new space/generation with quality gates, never by mutating vector semantics in place.

## Verification
R10,R28-R31,R40-R42; E04,E21-E24,E34-E36. Local CPU execution, token spans, exact pgvector/RRF and explicit generation changes are implemented; see docs/local-retrieval.md and tests/test_encoder.py / tests/test_vector_index.py. ANN, reranking, caches, automatic backfill and pretrained quality acceptance remain pending.
