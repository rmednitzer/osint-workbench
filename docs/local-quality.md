# Frozen local retrieval diagnostics

This profile executes an offline lexical baseline and, when explicitly supplied,
a local ONNX encoder against a frozen ranking suite. It supplies execution evidence
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

The encoder embeds each complete passage using its document template and each
query using its query template. No text is truncated. Exhaustive normalized dot
products determine order, with document ID breaking ties. This isolated diagnostic
does not execute PostgreSQL full-text search, hybrid RRF, reranking or MCP.

The encoder has no validated abstention policy. It always returns the top-k corpus
documents, even for unsupported questions. Consequently, its unsupported-question
gate is expected to fail. Do not remove those questions or introduce a score
threshold fitted to their outcomes. An abstention policy needs separate development
and independent evaluation before it can support acceptance.

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
`quality.run(suite, output, encoder=None, budget_seconds=120, source_revision=None)`.
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
`encoder-document-NNN.json` or `encoder-query-NNN.json` before the next call.
Observations contain IDs, protocol hash, elapsed time and query scores, without
vectors or model paths. Complete systems also write prediction, score and
evaluation files. `completed.json` or `failed.json` records phase and completed
counts. Failure preserves completed observations; it does not invent aggregate
metrics for an unfinished encoder run. Errors use bounded codes, without raw
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
