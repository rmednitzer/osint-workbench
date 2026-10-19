# Local generation, proposals and reviewed products

The implementation includes an optional native llama.cpp completion adapter, local ONNX pair
reranking, durable model proposals, evidence spans, append-only operator reviews and
deterministic cited assertion digests. It does not establish pretrained semantic quality,
autonomous fact acceptance, general entity resolution or a deep-analysis briefing service. No
model, feed list, cloud account or private runtime is bundled.

## Local generation authority

A private `GeneratorManifest` declares the Unix socket path, peer UID, runtime binary
SHA-256, declared runtime source revision, local GGUF path/hash and expected model
alias, context/output budgets, timeout and literal prompt prefix/suffix. Supply a
single-model, one-slot llama.cpp server under operator management, with no external
clients sharing its slot. Use a private socket directory and permissions excluding
world access. The workbench neither starts that deployment nor changes its settings.
It never sends tool calls, shell commands or arbitrary model endpoints. No TCP route
or cloud fallback exists in this adapter.

Each connection checks the socket type/owner/mode and Linux peer credentials. It hashes
the peer process executable through the kernel `/proc` link against the manifest.
The native `/props` response must match the configured model file path, one-slot
contract and minimum context. The local GGUF file hash must match. This is a local
operator/executable/file identity boundary, not cryptographic attestation of all
loaded libraries, live weights, source-to-binary provenance or remote legal control.
The declared source revision alone does not prove a binary was built from that source.
Operators must validate/mirror the runtime and model supply chain and prevent another
client or administrator from reconfiguring the trusted server during a request.

The adapter preflights native tokenization, reserves output tokens, uses a fixed native
completion route and schema, and validates complete bounded output independently.
It rejects context overflow, truncation, token-limit stops, wrong aliases, malformed
JSON and schema errors. HTTP calls share an absolute deadline, identity encoding and
a 1 MiB response bound. Generated text is bounded separately. No response exception
text, prompt, source body or server metadata is written to diagnostic errors.

Before dispatch, it fsyncs a private ownership receipt under the same admission lock used by
encoders/rerankers. A response with the expected alias and recognized terminal stop type
releases that receipt before generated content/schema validation; a completed but invalid model
result therefore differs from an uncertain native outcome. A client crash, disconnect or
uncertain response leaves it in place, blocking subsequent shared admission. A timeout does not
prove daemon termination. Explicit operator `enrich reconcile` checks the configured owner,
previous process identity and an idle native slot before clearing the receipt. It cannot clear
another manifest's ownership or a still-live prior process merely because a replacement socket
looks idle. Lock paths/users/hosts must be configured consistently; this is not a multi-host
scheduler. Use the [marker custody and recovery protocol](inference-marker-safety.md); do not
delete a marker or switch lock paths merely to bypass a reservation.

Native tokenization treats source-bearing prompt text as literal content with
`parse_special=False`; only the separately configured trusted prefix/suffix may
contain control tokens. Completion receives the exact validated integer-token
sequence, with one shared deadline and final context bound. The runtime verifies
that automatic special tokens are a bounded prefix only; automatic suffixes or
other transformations fail capability validation. This is not generic chat-template
support or semantic prompt-injection resistance. See
[ADR-0045](adr/0045-bounded-operational-profile.md).

The tokenization policy version participates in generator identity. Old queued
enrichment jobs keep their prior identity/kind and are not claimed by this new
generator. Explicit enqueue creates a new identity-bound job; operators must
review the disposition of old queued jobs. No automatic reset or migration occurs.

## Enrichment and graph contract

The operator enqueues a document using a private generator manifest. The job kind and dedup key
bind document/snapshot, generator identity and prompt version. The enrichment worker claims only
that identity, verifies original evidence and rejects oversized source input (more than 16000
code points). Result acceptance checks that the source is still an active head; this is not a
guarantee that obsolete-but-retained versions can never consume inference before that final
check. The local route supplies no model tools, provider keys or arbitrary file/URL arguments.
The same enrichment worker also supports an explicitly selected governed cloud route with
operator policy, classification and credentials; that distinct disclosure boundary is documented
in [cloud routes](cloud-routes.md). There is no implicit escalation from this local adapter to
that route. A prompt delimiter is not treated as an injection defence. The write boundary
accepts only the versioned typed schema and original-text evidence spans.

Proposals contain bounded subject/predicate/object labels, statement, polarity and quotation.
The ontology currently supports `mentions`, `affects`, `mitigates`, `deadline` and `related_to`.
Claims preserve asserted, negated or uncertain polarity. Quotations are located in original
Unicode coordinates; the actual source slice is stored. Schema or evidence failure rejects the
whole operation rather than accepting a valid prefix. Quotation location allows case-folding and
inter-token whitespace differences, then stores the actual original slice; it selects the first
matching occurrence, not an independently disambiguated mention. An empty claims list is visible
abstention. A failed/cancelled job is not silently restarted: an operator can enqueue a new
intentional `--operation-id`, preserving the prior operation and its outcome. Reusing an
operation ID is idempotent. Proposals and fenced job completion commit atomically. Cancellation
or expired ownership prevents late acceptance. Errors retain bounded codes; malformed model text
is not silently repaired or stored as accepted fact.

A matching quotation proves its location, not truth or semantic entailment. Model proposals stay
pending until an operator appends an accept/reject review with rationale and an intentional
actor label. This actor field is attribution, not a new authentication mechanism; the database
writer credential supplies authority. The same writer can create a proposal and review it;
independent reviewer identity and role separation remain unresolved, as recorded in the audit
backlog. MCP cannot review or create assertions. Different labels or sources are not
automatically merged, and fuzzy names do not establish common identity. Assertion
reads use `ontology_version=assertion-proposals/2` and
`entity_resolution=not-performed`. The `subject_label_binding_id` and
`object_label_binding_id` hashes bind the proposal label and its role to the
source document and supporting quotation span. Labels need not occur in that
span: these are neither label-specific coordinates nor resolved entity IDs.
The v2 contract replaces misleading v1 mention fields; see
[client migration](mcp-read-contract.md#assertion-label-bindings) and
[ADR-0051](adr/0051-honest-assertion-label-bindings.md). Alias, merge and contradiction workflows
remain required future work. Negated and uncertain assertions are not collapsed into positive
facts.

```sh
osint-workbench enrich enqueue --manifest /private/generator.json --document-id DOCUMENT_SHA256
osint-workbench enrich work-once --manifest /private/generator.json
osint-workbench review ASSERTION_SHA256 --decision accept --actor REVIEWER --rationale 'Evidence reviewed'
osint-workbench briefing create --document-id DOCUMENT_SHA256
osint-workbench briefing show --briefing-id BRIEFING_SHA256
osint-workbench enrich reconcile --manifest /private/generator.json
```

A briefing is a deterministic `reviewed_assertion_digest`, not a model-written analysis.
It contains accepted statements, polarity and exact quotations with document/snapshot
IDs and offsets. It records a corpus cutoff and explicitly unassessed source diversity.
The projection is deterministic given accepted assertions and its recorded cutoff;
a new creation records a new cutoff. No accepted assertions yields a degraded empty digest; pending claims are never promoted
as fallback. Reads verify the content digest, item fields and selection membership,
compare every item with the live accepted assertion it cites and verify the quoted
evidence. Assertions accepted after the recorded cutoff are not treated as omissions. Withdrawn reviews or obsolete
source versions make a cited product stale. Private reviewer rationale and actor labels
are excluded from MCP/products. Old source evidence and review history remain retained.
No outbound publication is enabled. Full topic selection, MMR/family independence,
semantic entailment evaluation and context retention remain open.

## Reranking

`OW_RERANKER_MANIFEST` explicitly enables a local ONNX pair scorer. The private manifest
binds model/tokenizer paths and hashes, output tensor name, positive logit class,
input token budget and thread limit. The model must accept int64 IDs, optional masks
and token type IDs, and produce one score or a class-logit row. Template processing
belongs to the supplied tokenizer JSON. The adapter disables truncation, verifies
files and shapes, rejects nonfinite values and uses bounded CPU child execution with
shared admission. It returns raw ordering scores, never confidence or probability.

Search reranks up to 32 configured lexical/hybrid candidates, using each candidate's
first 1000 original code points. The returned `rerank_input` makes that partial-text
boundary explicit. Requests outside the rerank paging/token limits fail; no silent
profile fallback occurs. Pretrained relevance, long-document coverage and calibration
still need independent held-out evaluation.

## Verification boundary and recovery

The optional native test dependency is prepared explicitly from a fixed source commit
and archive digest. CI disables UI fetching/building, cloud download support and GPU
use, then builds the native CPU server. Tests generate a tiny constant-weight GGUF;
no pretrained weights are downloaded. Actual constrained generation checks execution,
not language understanding. Recording Unix-socket fixtures cover malformed/truncated
responses, unknown outcomes, permissions and idle reconciliation. Actual ONNX pair
scoring uses a separate synthetic numerical oracle. PostgreSQL/MCP tests cover proposal
validation, abstention, review withdrawal, source changes and cited product reads.

Core migration v3 originally added these tables and grants; the current core schema is v10.
Published earlier SQL remains unchanged. Reader credentials cannot write
proposals/reviews/products or read private review rationale. Preserve tables and history on
rollback; disable optional manifests and workers to return to core reads. Do not downgrade
schemas destructively. Complete operational backup/restore and all-copy erasure remain open
beyond the implemented [bounded recovery](recovery.md), [lifecycle/holds](lifecycle.md) and
separate [SQL purge](retired-record-purge.md). Autonomous quality gates, full GPU resource
ownership and remote MCP remain open. The bounded governed cloud adapter and settlement ledger
are implemented separately; native vendor adapters, streaming, batches and live-provider
acceptance remain open in [cloud routes](cloud-routes.md).

Native API reference: [llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/620d2225cc436ab0b001e3200e590e3b286ef9ab/tools/server/README.md).
