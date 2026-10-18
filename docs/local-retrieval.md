# Local CPU retrieval profile

This optional profile provides local ONNX embeddings, token-aware spans, an exact
pgvector cosine ranking, lexical/rank fusion and explicit generation activation.
It is a bounded reference implementation, not a complete high-scale or semantically
accepted search deployment. No pretrained model is shipped or downloaded at runtime.
Tests generate a small ONNX graph and tokenizer with independently defined vectors;
this proves execution/numerical/provenance behavior, not language understanding.

## Provision and configure

Install the `retrieval` Python extra. Provision pgvector binaries from a reviewed
source in PostgreSQL 18, without already installing the extension in another schema.
`osint-workbench migrate-retrieval` uses the migration-only credential to install the
optional extension into a dedicated schema. The core migration never requires it.
An existing extension elsewhere is refused instead of silently relocated. This is a
new optional schema; do not remove it or downgrade after retaining derived records.

Keep the encoder manifest outside Git. It has `schema_version: 1`, local `model_path`
and `tokenizer_path`, SHA-256 fields `model_sha256` and `tokenizer_sha256`, `max_tokens`,
`overlap_tokens`, `output_name`, `threads` and an embedding `space` object. The latter
contains model/tokenizer revisions (the actual file digests), literal query/document
templates with exactly one `{text}` slot, `pooling` (`mean`, `cls` or `pooled`),
`dimensions`, `normalized: true`, `metric: cosine`, `precision: float32`. The tokenizer
must be a Hugging Face Tokenizers JSON file. The ONNX model must have int64
`input_ids`, optionally `attention_mask`/`token_type_ids`, and the named pooled or
per-token output. Unsupported contracts fail. Identity includes every semantic/split
parameter and artifact digest, excluding host paths and execution thread count.

Only supplied model/tokenizer files are opened; both are verified before use. The
model is loaded from bytes, with external weight files unsupported. Model files and
native inference are trusted operator inputs; resource limits are not a model sandbox.
There is no `trust_remote_code`, hub login, cloud fallback or automatic model fetch.
Verify provenance, licence, export conversion/pooling, tokenizer and quality before use.

```sh
osint-workbench index build --manifest /private/encoder.json
osint-workbench index activate --manifest /private/encoder.json --generation GENERATION_UUID
```

Set private `OW_ENCODER_MANIFEST` for CLI/MCP hybrid search. If it is absent, the core
search remains lexical. If supplied but broken or mismatched, the call fails visibly;
there is no silent fallback. A query does not build an index or call a remote provider.
MCP exposes seven read tools; operator indexing, switching and cancellation are
not agent tools. Hybrid search accepts offsets 0–200 over two bounded candidate pools
of at most 100 documents each. Scores are reciprocal-rank fusion values, not confidence.

## Admission and failure contracts

Encoder operations acquire a nonblocking OS file lock before spawning a child. Default
lock is per local UID; services sharing CPU capacity must share the same trusted UID
and `OW_INFERENCE_LOCK` file on the same host. Separate users/hosts/lock paths do not
share admission. Contention reports `INFERENCE_BUSY` without a queue or fallback.
This is one-slot encoder admission, not a GPU or cross-workload scheduler.
Each child has 40 CPU seconds, 4 GiB address space, a 16 MiB result bound and 45 s
wall deadline. Expired children are killed/reaped. Each encoder/reranker child
sets a Linux parent-death SIGKILL itself and refuses work with
`INFERENCE_PARENT_UNBOUND` unless its parent is the process that holds admission,
so a killed parent cannot release admission while its child keeps computing. A
signal or resource-limit exit is reported as `ENCODER_UNAVAILABLE` or
`RERANK_UNAVAILABLE`, never as an invalid model result. The SIGKILL can arrive
just after the dead parent's lock is released; this is a bounded race, not a
cross-process scheduler. Files are bounded to 512 MiB model
and 16 MiB tokenizer. Unsupported shapes, zero/nonfinite vectors and oversize query
inputs fail. Tokenizer truncation is disabled; chunk fitting rechecks the templated
input budget and stores exact original Unicode offsets and slice hashes.

Parent and child share a 2 MiB complete UTF-8 JSON packet limit. The parent checks
serialized bytes before admission; the child reads one extra byte to detect an
oversized valid prefix and rejects malformed, duplicate-key or truncated packets
before model session creation. Character, token and result bounds remain separate.

Index builds are explicit operator operations, bounded to 1000 current documents,
2 million code points in aggregate, 200000 per document, 512 chunks per document
and 4096 chunks per generation. Aggregate limits fail instead of truncating the
corpus. A document the encoder refuses because of its own content (blank or
over-long input, packet/chunk/result bounds, tokenizer offsets, or a zero-norm
vector from unknown-only text) is kept as a member with a recorded reason in
`ow.retrieval_exclusions` instead of failing the build. Integrity,
compatibility, timeout and availability failures still fail it, and a build in
which more than half the members would be excluded fails with
`RETRIEVAL_EXCLUSION_LIMIT`. Builds, index status and hybrid search report
`excluded_documents`; excluded documents remain lexically searchable and
readable as evidence. See [ADR-0041](adr/0041-explicit-retrieval-exclusions.md). Partial
builds stay inactive and are marked failed; a process crash can leave an inactive
building record. No automatic resumer/cleanup exists yet. Search uses exact pgvector
scans and PostgreSQL statement timeouts; no ANN performance claim is made.

The build retains immutable document IDs and model identity. Activation requires ready
state, compatible encoder identity, matching current document set and vectors or a
recorded exclusion for every member. Active generation changes in one transaction. Rollback uses the same activation
checks; a generation for an outdated corpus cannot be activated. Search checks its
own repeatable-read corpus snapshot, excludes obsolete document heads and explicitly
marks corpus drift degraded. Later concurrent collection can create normal drift;
operators must rebuild and activate. Growth past the reference build bounds also
reports degraded drift rather than failing search, because no generation can
exceed those bounds; builds and activation still refuse the oversized corpus. Old generations remain retained for review.

## Supply-chain and sovereignty boundary

All document inference is local; this path sends no input to a model registry or cloud
API. ONNX Runtime is a Microsoft-origin open-source native dependency; Tokenizers and
its packaging dependencies have foreign upstream and build/distribution dependencies.
Local execution does not establish EU control of that supply chain. Operators must
review/build/mirror dependencies and approve the model's provenance and licence.
No EU-sovereignty or regulatory-conformance claim is made for an arbitrary bundle.
The portable ONNX/tokenizer and PostgreSQL data contracts support replacement/exit;
conversion accuracy and numerical compatibility still require validation.

## Verification and remaining acceptance

Identical overlapping `LocalEncoder.query` calls on one encoder instance share
one verified native computation under [ADR-0034](adr/0034-bounded-query-coalescing.md).
The exact validated query packet binds the flight; owners/waiters and wait time
are bounded. Followers receive independent vector copies. No completed cache is
retained, so later calls verify model files again. A waiting caller's timeout does
not cancel the owner. This adds no cross-process scheduling, persistent cache,
new MCP authority or semantic-quality claim.

`tests/test_encoder.py` executes actual ONNX Runtime CPU inference and validates exact
fixture vectors, Unicode spans, hashes, no silent truncation, zero-vector rejection
and admission release. `tests/test_vector_index.py` uses native pgvector and a real
MCP client to test build/switch/rollback, corpus drift, failed-build isolation and
reader permissions. CI installs the built wheel with hash-locked dependencies and
a digest-pinned disposable PostgreSQL/pgvector service. This is not a pretrained
English/German relevance evaluation or GPU test. Bounded synthetic reranking and
native text generation also ship; see local-intelligence.md. Pretrained model
adoption/calibration, held-out quality, ANN scaling and automatic backfill/caches
remain open in the full roadmap.

API references: [ONNX Runtime](https://onnxruntime.ai/docs/api/python/api_summary.html),
[Tokenizers](https://huggingface.co/docs/tokenizers/python/latest/api/reference.html),
[pgvector](https://github.com/pgvector/pgvector).
