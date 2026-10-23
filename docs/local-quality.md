# Frozen local retrieval diagnostics

This profile executes an offline lexical baseline and, when explicitly supplied,
a local ONNX encoder or stand-alone reranker against a frozen ranking suite. It supplies execution evidence
and narrow diagnostic measurements. It does not accept a model, activate an index,
select a production route, or close the semantic-quality programme.

## Frozen public inputs

`config/evaluation.example.json` contains six authored synthetic English/German
passages and eight queries. Each split contains three answerable cases and one
unsupported question. All corpus documents have an explicit relevance grade for
every query; grade zero includes counterexamples. Cases cover project identity,
version boundaries, negation, retention and absent information.

The canonical validated suite SHA-256 is:

```text
74e962126c56ae643f8d32e2dba4009c05c661a9162997c49320302b4c43b8d0
```

This is the hash returned by `evaluation.digest(Suite)`, not the raw JSON file
hash. Whitespace and object-key order do not alter it. Corpus text, queries,
judgments, targets, cutoff and label protocol all contribute to the hash.

The predefined cutoff is 3. Each split requires recall >= 1.0, MRR >= 0.8,
nDCG >= 0.8 and explicit unsupported-query abstention >= 1.0. These values were
written before model execution. Changing any target creates a different suite;
retain the original result and explain the change rather than tuning against it.

`held_out` means a separate frozen query group here. These cases are public,
authored with AI assistance, and visible alongside development cases. They are
neither secret nor independently human-labelled; their shared corpus is deliberate.
Passing cannot establish generalization, independent semantic quality, production
utility, or English/German coverage beyond these eight questions. The suite does
not measure citation support, briefing omissions, domain correctness or source
diversity. Those acceptance obligations remain open.

## Metrics and replay contract

For answerable queries, recall@k is the number of returned positive-grade documents
divided by all positive-grade corpus documents. MRR@k is the reciprocal rank of the
first positive-grade result, or zero when none appears. nDCG@k uses gain
`2**grade - 1`, discount `log2(rank + 1)`, and an ideal ranking over the complete
judged corpus. Metrics are macro-averaged separately for each split. Grades are
integers 0 through 3; positive grades are relevant for recall and MRR.

Unsupported queries are excluded from those three means. Their separate rate
requires an explicit abstention with an empty ranking. An empty ranking without
abstention fails that check. A missing answerable or unsupported population yields
null metrics/gates and cannot make `all_targets_met` true.

A prediction JSON has `format: 1`, `suite_sha256`, `system_id`,
`system_manifest_sha256`, and `rankings`. Every suite query appears exactly once.
Each ranking has `query_id`, `abstained`, and an ordered `document_ids` list. Scores
are separate observations, not relevance labels or confidence. Unknown or duplicate
IDs, incomplete judgments, duplicate JSON keys, nonfinite numbers, extra fields,
and mismatched suite hashes are rejected. Declared leakage groups and normalized
exact query text cannot cross splits. This detects neither undeclared semantic
paraphrases nor training contamination.

Replay existing predictions without any model execution:

```sh
osint-workbench evaluate replay \
  --suite config/evaluation.example.json \
  --predictions /tmp/ow-diagnostic/lexical-predictions.json \
  --file /tmp/ow-replay.json
```

The destination must be absent. The receipt binds the suite, predictions, supplied
system-manifest identity, scorer version, per-query results and split gates.
Hashes bind the supplied data; they do not attest the truth of the supplied model
provenance or independently validate the labels.

## Paired replay comparison

Compare two complete prediction files on exactly the same frozen suite without
executing models, loading their configuration or accessing the database:

```sh
osint-workbench evaluate compare \
  --suite config/evaluation.example.json \
  --baseline /tmp/ow-lexical-diagnostic/lexical-predictions.json \
  --candidate /tmp/ow-encoder-diagnostic/encoder-predictions.json \
  --file /tmp/ow-paired-comparison.json
```

The absent destination is created privately without overwrite. The format-1
`paired_ranking_comparison` receipt binds the suite, scorer, comparison policy,
both prediction digests, declared system/manifest identities and both replay
receipt digests. It includes their existing split summaries/target gates,
candidate-minus-baseline aggregate deltas, per-query deltas and split-level
improved/regressed/unchanged counts for each metric. Pairing uses query IDs;
prediction order is immaterial. Positive deltas mean a larger measured metric,
not model acceptance. Ties use exact equality of the deterministic scored values.

Answerable and unsupported queries retain separate metric populations. Missing
populations yield null deltas and zero paired counts; they do not become ties or
passing gates. Both prediction files must satisfy the existing exact coverage,
suite-hash and ranking contracts. The Python API is
`evaluation.compare(suite, baseline, candidate)`.

Exit 0 means a valid comparison was written, including when both systems fail
all targets or the candidate regresses. Exit 1 indicates invalid input or failure
to write the receipt. Unlike replay/local execution, comparison does not use exit
2 for numerical target failures. Inspect the embedded gates and paired results.
The CLI prints only receipt identity and the semantic-acceptance limitation.

This is descriptive evidence for the supplied fixed cases. It estimates no
confidence interval, statistical significance, population effect or causal effect.
Query counts are not independent replicates when cases share sources or leakage
groups. The receipt does not verify label independence, truthful system provenance,
fair resource use or actual model execution. Retain protocols and raw observations;
a paired receipt alone cannot establish those conditions.

## Independent qualification prerequisites

The public diagnostic remains exposed development evidence. Before running an
acceptance comparison, the evaluator must record a separate protocol that fixes:

- The intended deployment decision, workload/languages, unit of analysis, source
  or topic clusters, sampling frame, scope of inference and material exclusions.
- The label custodian and separation from implementation/model tuning; who has
  seen each query group, any prior exposure, and the access/release procedure.
  Keep controlled held-out queries and labels outside the public repository.
- Independent assessor instructions for grades 0–3, answerability and evidence
  support; preserve original judgments, disagreements and adjudication provenance.
  An LLM judge may supplement these records; it is not the independent oracle.
- The suite, cutoff, targets, baseline and candidate identities, permitted corpus
  and resources, scorer/comparison version and source/environment identities,
  all frozen before inspecting held-out predictions. A declared
  `independently_labelled` value is an assertion requiring external custody evidence.
- A development-only answerability policy, including calibration and refusal
  behavior. Do not fit score thresholds to held-out failures or remove unsupported
  queries after seeing results. Record tuning and contaminated/excluded cases.
- The primary metric and decision margin, regression limits, uncertainty method
  appropriate to independent units/clusters, sample-size rationale and stopping
  rule. The paired command supplies descriptive measurements, not that analysis.
- Failure, timeout, missing-output and retry handling; preserve unsuccessful
  attempts. Partial prediction sets cannot silently disappear or pass replay.
  Record deviations and distinguish exploratory follow-ups from frozen evaluation.

Execute with the same permitted workload/resources for both systems, preserve
raw predictions and execution journals, recompute replay/comparison receipts, and
review failures alongside resource costs. A criterion failure keeps adoption open;
repeat only under a separately identified protocol with the original retained.
A pass supports only the declared workload and conditions. Production-cascade
retrieval, citation support, briefing omissions, actual deployment and sovereignty
remain separate acceptance obligations. No independent dataset, custodian,
statistical power or adopted model is established by this prerequisite list.

## Execute local diagnostics

The lexical-only path requires no model, database, network, credentials or retrieval
extra. It normalizes text using Unicode NFKC and case folding, ranks by the number
of shared distinct alphanumeric tokens, and breaks ties by document ID. It returns
only positive-overlap results and abstains when there are none. It has no stemming,
stop-word model or language-understanding claim.

```sh
osint-workbench evaluate local \
  --suite config/evaluation.example.json \
  --output /tmp/ow-lexical-diagnostic \
  --budget-seconds 120
```

With a reviewed, hash-bound local encoder manifest:

```sh
osint-workbench evaluate local \
  --suite config/evaluation.example.json \
  --output /tmp/ow-encoder-diagnostic \
  --encoder-manifest /tmp/ow-public-model/encoder.json \
  --budget-seconds 240
```

`--source-revision` optionally records the exact 40-character lowercase Git commit
identity. It is an operator-supplied provenance assertion. Keep output outside Git
and use a new directory for every run. Its parent must already exist.

The runner revalidates and owns a deep encoder-manifest snapshot, including the
embedding space and templates, before creating output. Caller-side configuration
changes cannot rebind later native calls or the recorded prediction identity.
Each run uses its own built-in adapter rather than the caller's active query
flights or subclass overrides; native artifact checks and shared admission remain
in force. Invalid nested configuration is refused before output is created.

The encoder embeds each complete passage using its document template and each
query using its query template. No text is truncated. Exhaustive normalized dot
products determine order, with document ID breaking ties. This isolated diagnostic
does not execute PostgreSQL full-text search, hybrid RRF or MCP. It
also does not exercise profile-v5 exclusion/activation behavior: a failed complete
passage embedding stops this diagnostic instead of becoming an index exclusion.

The encoder has no validated abstention policy. It always returns the top-k corpus
documents, even for unsupported questions. Consequently, its unsupported-question
gate is expected to fail. Do not remove those questions or introduce a score
threshold fitted to their outcomes. An abstention policy needs separate development
and independent evaluation before it can support acceptance.

## Stand-alone reranker diagnostics

With a reviewed local ONNX pair-scoring manifest:

```sh
osint-workbench evaluate local \
  --suite config/evaluation.example.json \
  --output /tmp/ow-reranker-diagnostic \
  --reranker-manifest /tmp/ow-public-model/reranker.json \
  --budget-seconds 240
```

The encoder and reranker options are independent; supplying both compares three
systems. The reranker scores the **complete corpus**, not an encoder or lexical
candidate shortlist. This isolates pair scoring; it does not qualify the production
retrieval cascade, candidate recall or filters. Its character bounds are 1,000 per
complete passage and 2,000 per nonblank query, checked before creating output.
Long input is refused, never shortened. Model-token limits can still refuse a call.

The runner owns a validated manifest snapshot. Protocol format 2 binds the
reranker identity, threads and versioned complete-corpus/descending-score policy.
Its prediction identity hashes both model identity and ranking policy; paths are
excluded. Results must contain exactly the submitted corpus IDs and finite scores.
Each query durably writes `reranker-query-NNN.json`; a complete run also writes
`reranker-predictions.json`, `reranker-scores.json` and `reranker-evaluation.json`.
Earlier lexical/encoder receipts and completed query observations survive a later
reranker failure. An incomplete reranker receives no aggregate evaluation.

Reranker scores do not establish confidence or answerability. This rank-only
profile also returns documents for unsupported questions and fails their abstention
gate. Keep those questions and negative results; model adoption still requires
independently controlled labels, calibration and actual deployment acceptance.
No model is selected/downloaded and no API/cloud route is called. Existing local
inference admission remains in force. See [ADR-0055](adr/0055-frozen-reranker-diagnostics.md).
Lexical/encoder-only calls retain their existing protocol format 1.

The CLI exits 0 when execution completes and all numerical targets pass, 2 when
execution completes with unmet targets, and 1 on recorded execution failure. Schema
or configuration errors also fail. A successful process or numerical gate does
not change the explicit `semantic_acceptance` limitation in the receipt.

## Explicit public artifact preparation

`scripts/prepare_encoder.py` is an opt-in network operation, separate from package
imports, default CI, runtime evaluation and application startup. It downloads the
pinned public `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` ONNX
model and tokenizer, verifies exact byte sizes and SHA-256 digests, and writes a
local manifest. It does not activate or establish inference compatibility.

The upstream artifact revision is
`e8f8c211226b894fcb81acc59f3b34ba3efd5f42`. The two files total 479383128 bytes.
Inspect the script's fixed identities and the
[immutable upstream artifact card](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/blob/e8f8c211226b894fcb81acc59f3b34ba3efd5f42/README.md)
before choosing to prepare them:

```sh
python scripts/prepare_encoder.py \
  --output /tmp/ow-public-model \
  --accept-license Apache-2.0
```

The explicit licence acknowledgement covers the published model-card declaration;
it is not an assessment of complete training-data rights. The lineage includes
[Microsoft Multilingual MiniLM](https://huggingface.co/microsoft/Multilingual-MiniLM-L12-H384).
These experimental artifacts and their distribution do not establish an
EU-controlled or independent supply chain. Local inference avoids sending the
suite text to a hosted inference API; it does not establish digital sovereignty,
complete model provenance, or production approval. A sovereign deployment needs
its own provenance, licence, jurisdiction, distribution, exit and quality decision.

The manually dispatched `Run public encoder diagnostic` workflow performs this
same explicit download and installed-wheel CPU execution. Push/PR CI does not
trigger it. It verifies the frozen suite hash before preparation, preserves a
negative numerical gate as an observation, and uploads only the public synthetic
run outputs for 14 days. Model weights are excluded. Do not reuse that public
workflow with private corpora or operational inputs. A green workflow means the
diagnostic completed with receipts, not that its quality targets passed.

## Evidence, bounds and failure handling

The Python APIs are `evaluation.parse_suite(bytes)`,
`evaluation.parse_predictions(bytes)`, `evaluation.digest(model)`,
`evaluation.evaluate(suite, predictions)`, and
`quality.run(suite, output, encoder=None, budget_seconds=120, source_revision=None, *, reranker=None)`.
The evaluator accepts at most 8 MiB per input, 200 corpus documents, 500 queries,
20000 judgments and 100 returned IDs per query. The execution runner imposes a
smaller limit of 32 documents and 32 queries. Input text is bounded and rejected
rather than silently shortened.

The runner creates an absent output directory with mode 0700 and files with mode
0600. It writes and fsyncs `suite.json` and a SHA-bound `protocol.json` before
ranking. The protocol includes policies, budget, model identity, thread count,
software versions, optional source revision and limits. The budget is checked
before each operation; an admitted native call can exceed it by that call's
existing 45-second timeout. Timings describe the measured execution only and are
not service-level or representative performance claims.

Each successful native document/query call durably writes
`encoder-document-NNN.json`, `encoder-query-NNN.json` or
`reranker-query-NNN.json` before the next call.
Observations contain IDs, protocol hash, elapsed time and query scores, without
vectors or model paths. Complete systems also write prediction, score and
evaluation files. `completed.json` or `failed.json` records phase and completed
counts. Failure preserves completed observations; it does not invent aggregate
metrics for an unfinished model run. Errors use bounded codes, without raw
exception strings. A process killed before its terminal receipt leaves an
incomplete journal requiring operator inspection.

No file is overwritten or automatically resumed. Filesystem failures can prevent a
terminal receipt from becoming durable; inspect all existing outputs and start a
new run directory after resolving the fault. Preserve original receipts when
comparing changes. Cancellation, retries, downloads or production index activation
are not implied by these commands.

## Recorded attempts

[Profile diagnostic evidence](testing/profile-diagnostics.json) preserves attempts
separately from native regression CI. The first pretrained attempt stopped before
inference with `DOWNLOAD_DESTINATION_REFUSED`. A no-follow HEAD request to the
immutable model URL identified the exact public artifact CDN `us.aws.cdn.hf.co`.
The follow-up admits only that hostname, retaining the original revision, byte
limits, hashes, suite, targets and runtime constraints. No inference or quality
result is inferred from artifact metadata or preparation failure.

The follow-up run at revision `307766f` completed six document and eight query
calls using the pinned pretrained bytes. Both the encoder and lexical baseline
produced the following aggregate measurements; raw rankings, scores, timings,
protocol and replayable receipts are preserved in
[the public observation directory](testing/public-encoder-diagnostic-307766f/).

| Split | Recall@3 | MRR@3 | nDCG@3 | Unsupported-query abstention |
| --- | ---: | ---: | ---: | ---: |
| Development | 1.0 | 0.833333 | 0.876977 | 0.0 |
| Exposed held-out | 1.0 | 1.0 | 1.0 | 0.0 |

Both systems failed the frozen abstention target. Workflow success means completed
execution with retained negative gates. These eight cases demonstrate no aggregate
relevance improvement over this lexical baseline. They do not establish statistical
equivalence or population performance. Encoder execution does not validate
production chunking, pgvector, hybrid RRF, reranking, briefing or citation quality.
An independently designed answerability policy, independent labels, representative
resources and an adopted model/sovereignty decision remain open.

The workflow now defaults to the separate `reference-service` profile. Select
`public-encoder` or `both` explicitly when repeating the artifact/inference
experiment; a deployment-only dispatch does not download or rerun the encoder.
