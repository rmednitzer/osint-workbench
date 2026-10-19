# Operator-controlled local inference API

This opt-in generation profile connects existing compatible chat servers over
loopback HTTP or TLS to a configured private IP. Native llama.cpp Unix-socket
generation and local ONNX embeddings/reranking remain available independently.
This is a client integration, not a deployed inference server, embedding API or
remote MCP service. See [ADR-0052](adr/0052-local-inference-chat-api.md).

## Qualify the backend before selection

The operator must qualify and retain private evidence for the actual server
revision, model weights/revision and licence, alias, chat template, JSON Schema
support, context limits, resource/concurrency limits, authentication and TLS.
Disable remote model forwarding, provider sessions and metered upstreams; verify
that server/container egress prevents unintended external inference. A local
Ollama address can forward to cloud models. IP locality and EU hosting alone
prove neither local execution nor sovereignty. Keep model/runtime configuration
under operator custody for the duration of work.

The manifest's qualification and model-revision digests identify those operator
records. The application cannot verify the server's live weights or forwarding,
billing, jurisdiction or library composition. The existing native socket profile
has stronger local executable/model-file checks. The API profile has no exact
native tokenizer preflight or literal-control-token guarantee. Separate chat
roles do not eliminate prompt injection. Schema and quotation checks establish
bounded proposal structure and located quotations, not entailment or truth.

Qualify the exact server/model combination. Ollama and vLLM document compatible
structured-output fields, but authored HTTP fixtures and the pinned native chat
test do not establish acceptance of every vendor version or pretrained model.
No model is fetched, pulled or started by configuring this profile.

## Private manifest

Store the JSON outside the repository. A synthetic loopback example follows;
replace the two evidence digests with the actual reviewed private records.

```json
{
  "schema_version": 1,
  "adapter": "local-openai-chat/1",
  "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
  "model": "synthetic",
  "operator_controlled": true,
  "remote_forwarding": false,
  "metered": false,
  "qualification_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model_revision_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "data_classes": ["public"],
  "max_input_bytes": 65536,
  "max_output_tokens": 1024,
  "timeout_seconds": 45
}
```

HTTP accepts literal loopback addresses. Private LAN endpoints require HTTPS,
a literal RFC1918 or IPv6 ULA address with a matching certificate IP SAN, and
`credential` using the existing [file/systemd references](api-acquisition.md#credential-custody).
Hostname discovery, public/link-local addresses, redirects and ambient proxies
are unsupported. Only `/v1/models` and `/v1/chat/completions` are called. Provider
or metered remote inference belongs to the separate [governed cloud profile](cloud-routes.md).

For a private CA, add `ca_path` and `ca_sha256`. The final path must be a bounded
regular file, without a symlink; its bytes must match the digest. Parent paths
remain operator-trusted. The configured CA replaces system roots for this client.
Otherwise verified system TLS trust is used. There is no insecure TLS option.
For bearer authentication, select a managed `credential` reference. A missing or
unsafe reference fails before network dispatch. Credentials never enter model
messages, durable markers or error text; exact active-token echoes in decoded
output are refused. This is not general secret detection or memory zeroization.

## Enqueue and work

Explicitly classify the input using a class permitted by the manifest:

```sh
osint-workbench enrich enqueue --local-api-manifest /private/local-api.json --document-id DOCUMENT_SHA256 --data-class public
osint-workbench enrich work-once --local-api-manifest /private/local-api.json
```

Select exactly one native manifest, local API manifest or governed cloud route.
A local API manifest does not select a cloud fallback. Workers claim only jobs
with its exact generator identity. Changing the endpoint, qualification, model,
trust or budgets creates another identity; old jobs are not rerouted. Credential
value/reference rotation alone does not select another identity. Unclassified
or denied input makes no API request. Existing accepted-job deduplication is not
a reset command. Enrichment enqueue reports `job_status`, `enqueue_effect` and
`requeued=false` from the same SQL statement. `terminal_preserved` means the
existing succeeded/failed/cancelled job was retained; `pending_or_running` reports
nonterminal work, not a new-dispatch promise. Later transitions can change that
state. Use a new intentional `--operation-id` to request a new operation.

The model-list probe checks the exact alias without submitting generation.
The POST uses non-streaming structured chat, a fixed system message and separate
user input, bounded input/request/response bytes, an output-token request and one
absolute network deadline. No tools/functions or automatic retries are sent.
Application byte bounds are not a server memory quota or context-fit proof.
Complete output must have one matching-model choice and a recognized terminal
reason. Truncation, refusal, tool calls and invalid schema accept no proposals.
Typed output still passes original-text quotation validation and fenced SQL
acceptance as pending review. This does not fix independent reviewer authority.

## Ambiguous outcome and explicit resolution

All cooperating local profiles use the same `OW_INFERENCE_LOCK` and private
custody protocol. Before the POST, an API receipt records only operation UUID,
generator identity and request hash. It contains no endpoint, credential, prompt
or source body. A timeout, disconnect, malformed/unrecognized completion or HTTP
error after submission retains the reservation. Further cooperating inference is
blocked even after the worker dies. A terminal application validation/refusal
error after a recognized completion releases admission. Job fencing still
prevents obsolete/cancelled results from being accepted.

First stop dispatchers. Use backend-specific operational evidence to establish
that the named request has terminated, or stop and verify the relevant backend
work. Retain a private evidence record and compute its SHA-256. A health/model
probe, caller timeout, job cancellation or idle unrelated backend is insufficient.
Then use the operation UUID from the private `.unknown` receipt:

```sh
osint-workbench enrich reconcile --local-api-manifest /private/local-api.json --request-operation-id REQUEST_UUID --confirm-terminated --termination-evidence-sha256 EVIDENCE_SHA256
```

The command records an **operator termination attestation**, not independent proof.
It writes/fsyncs a private `.resolved-REQUEST_UUID` audit beside the lock before
removing the exact marker. A retry after write-before-unlink failure accepts only
the identical evidence digest. Conflicting, unsafe or partial audit records stay
blocked and require private operator recovery. Preserve audit records under the
operator's retention/backup policy; they are not checkpointed or shared through
MCP. A resolved marker does not reset/retry the failed job or authenticate an
independent assertion reviewer.

[Native marker custody](inference-marker-safety.md) still assumes cooperating
trusted processes sharing one stable lock path. It is not a same-UID sandbox or
cross-host scheduler. Never remove/change the lock or bypass a reservation to
restore throughput. Before binary rollback, stop workers, establish termination
and resolve API receipts using this version; older clients refuse the new format.
