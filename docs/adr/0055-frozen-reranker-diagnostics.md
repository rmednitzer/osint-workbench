# ADR-0055: Frozen stand-alone local reranker diagnostics

Status: ACCEPTED for bounded offline CPU diagnostics. Date: 2026-10-19.
Runtime acceptance belongs to the exact candidate's installed/native checks.

## Context and criteria

The frozen quality runner can compare lexical and local encoder rankings, but
cannot exercise the implemented ONNX pair reranker. Model adoption needs repeatable
observations before independent quality acceptance. The diagnostic must bind its
model and ranking policy, preserve unsupported questions and failed numerical
gates, avoid silent truncation, and preserve earlier observations on failure.
No model selection, downloads, remote dispatch or production index changes follow.

## Alternatives

- No change: retains the encoder diagnostic but leaves reranker comparisons manual.
- Replay externally supplied rankings only: the existing evaluator supports this,
  but does not establish actual native pair scoring.
- Add a complete production cascade benchmark: needed for later retrieval acceptance,
  but couples candidate generation, SQL, filters and reranking before their individual
  effects can be inspected.
- **Selected:** opt-in exhaustive reranker scoring over the frozen bounded corpus,
  alongside the existing lexical and optional encoder diagnostics.

## Decision and trust boundaries

`evaluate local --reranker-manifest` selects the built-in local ONNX adapter.
The runner owns a revalidated manifest snapshot rather than sharing the caller's
mutable configuration. Each native invocation retains existing artifact verification,
CPU/process limits, parent binding and cooperative inference admission. An unresolved
inference reservation remains blocking; this command cannot clear it.

Every query scores all corpus documents, with complete untruncated text, descending
model output and document-ID tie breaking. At most 32 documents and 32 queries are
admitted. The selected profile additionally requires passages <=1,000 characters
and nonblank queries <=2,000 characters before creating output. Model-token limits
remain independently enforced at native execution. A score is not confidence.
No score threshold or learned abstention is introduced: unsupported queries still
return a ranking and fail the existing abstention gate.

The opt-in profile writes protocol format 2 with the reranker identity, threads and
explicit versioned policy. Prediction identity binds both model and ranking policy.
The existing lexical/encoder-only protocol remains format 1 without new fields.
Prediction/evaluation envelopes remain unchanged. Native results must contain
exactly the submitted corpus IDs and finite numeric scores before observation.

Private no-overwrite/fsynced files bind each completed query to the frozen protocol
before the next call. Failure preserves prior system receipts and per-query
observations without fabricating aggregate results for an incomplete reranker run.
Budget checks occur before each call; one admitted native call can exceed the
cooperative budget by its existing 45-second timeout. There is no hard total-I/O
deadline, automatic resume or automatic uncertainty resolution.

## Consequences, scope and reversibility

This enables reproducible rank-only execution diagnostics, not adopted useful-model
quality. The public authored labels are not independent human judgments. No
PostgreSQL hybrid/candidate-filter cascade, calibrated abstention, citation entailment,
GPU/backend qualification, model licence clearance or complete E23/E24 acceptance
is established. No remote API or cloud fallback is added. MCP retains seven reads.

The change affects an explicit CLI option and Python keyword. No database, grant,
source catalogue, dependency or deployment change. Ordinary lexical/encoder calls
retain their protocol. Rollback is a protected binary revert; preserve new private
format-2 journals as historical data. An older runner cannot execute the new flag
and must not silently relabel or resume those journals. Existing prediction replay
can still score its unchanged prediction envelope without executing a model.

## Verification

Reuse the actual synthetic ONNX pair fixture. Installed CLI execution must retain
the negative unsupported-query gate and correct numeric order, identity and private
file modes. Boundary cases refuse complete text outside the adapter bounds before
output. Late model-file tampering must retain earlier encoder/lexical receipts and
one accepted query while refusing incomplete aggregate results. An unsubmitted ID
must never become an observation. Caller-manifest mutation must not rebind a run.
Existing lexical/encoder, replay, inference admission and native process suites
remain applicable; no per-change test quota or broad parameter product is added.
