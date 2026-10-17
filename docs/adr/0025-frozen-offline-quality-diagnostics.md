# ADR-0025: Freeze offline ranking diagnostics before pretrained execution

Status: ACCEPTED for bounded diagnostic execution. Date: 2026-10-17.

## Context and decision drivers

Synthetic ONNX integration tests establish execution and numerical contracts. They
do not establish useful language retrieval, unsupported-question handling or
independent quality. The next increment needs reproducible observations without
silently selecting a provider, downloading a model on startup, exposing private
inputs or treating diagnostic results as model acceptance. ADR-0015's broader
independent acceptance and drift programme remains open.

## Alternatives and no change

No change preserves the current execution evidence and leaves pretrained behaviour
unknown. Model self-grading introduces a second unvalidated oracle. Reusing
production queries risks disclosure and evaluation leakage. A large benchmark
platform adds an authority and dependency boundary before the contracts are stable.
Choose small interoperable JSON replay, authored public diagnostic labels and an
explicit opt-in local executor. Human-independent, representative and genuinely
held-out acceptance remains a separate requirement.

## Decision

Freeze the complete corpus, query groups, graded judgments, cutoff and numerical
targets in one strict hash-bound suite before execution or model-result inspection.
Use an independently specified deterministic scorer for recall@k, MRR@k, graded
nDCG@k and explicit unsupported-query abstention, with split-specific macro means.
Require complete judgments, exact query coverage and explicit failure for invalid
or ambiguous inputs. Missing populations cannot produce a passing aggregate gate.

Always execute a fixed lexical overlap baseline. Optionally execute a supplied
hash-verified local ONNX encoder with document/query templates, complete text,
exhaustive normalized dot products and deterministic ID tie-breaking. Rank-only
model execution has no abstention threshold; unsupported cases are expected to
fail until a separately developed policy has independent acceptance evidence.
No model judge, output-derived threshold, implicit fallback or runtime download is
added.

Before ranking, durably record the frozen suite and protocol in a new private
output directory. Record identity, fixed policies, limits, budget, software versions
and an optional source revision. Persist each successful native document/query
observation before the next call, then publish complete-system evaluation receipts.
Preserve partial evidence and bounded failure codes when later operations fail.
Never overwrite, infer missing measurements or manufacture completion.

The public eight-query EN/DE suite is exposed, synthetic and authored with AI
assistance. Its `held_out` label denotes a disjoint frozen query group, not secret
or independent evaluation. Its canonical SHA-256 is
`74e962126c56ae643f8d32e2dba4009c05c661a9162997c49320302b4c43b8d0`.
It cannot close general semantic acceptance, citation or briefing-quality gates.

A separate manually invoked script/workflow may prepare pinned public experimental
artifacts. It requires explicit licence acknowledgement and verifies sizes/digests.
That experiment neither adopts non-EU model lineage or distribution as sovereign
infrastructure nor approves the model for production. No private sources, model
inventories, credentials, deployment inputs or operational datasets enter the
public diagnostic.

## Consequences, blast radius and reversibility

Only the operator CLI and isolated local execution path gain capabilities; MCP,
database schemas, active indexes, model routing and operational services do not.
CPU/memory/native-call bounds constrain execution; the overall budget is
cooperative and can overrun by one admitted 45-second call. Partial observations
consume bounded private storage. Hashes establish identity, not truthful provenance,
label independence, training-data rights or semantic correctness.

Retain the previous frozen suite, predictions and receipts when revising a model
or policy. Revert the diagnostic implementation without changing retained runtime
records or published migrations. Do not resume into existing output directories.
Production selection requires its own accepted quality and sovereignty evidence.

## Verification boundary

Regression tests cover independent metric arithmetic, strict input handling,
leakage checks, hashes, private no-overwrite persistence, bounded failures and
actual synthetic native ONNX execution. An opt-in pretrained workflow can add
revision-bound experimental observations. Neither test definitions nor this ADR
claim that workflow has run or that numerical/semantic targets have passed.
See [the execution protocol and limitations](../local-quality.md).
