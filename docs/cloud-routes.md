# Governed remote routes

> Bounded contract slice. See [ADR-0042](adr/0042-governed-compatible-cloud-route.md),
> [ADR-0043](adr/0043-remote-attempt-settlement.md) and STATUS for verified scope.
> Native vendor adapters, streaming, batches, invoice import and live-provider
> acceptance are not implemented.

The routed enrichment CLI is off unless all of the following hold: an operator policy
file outside Git, a route in it, the route's configured credential available through its selected channel, an
enrichment job explicitly enqueued for that route, and an explicit data class
on that job. The tracked `config/cloud-policy.example.json` has no routes and
therefore denies everything.

## Policy file

The file is at most 64 KiB, read without following a final symlink, and bound
to its SHA-256 in every ledger row. Money values are plain decimal strings below
1,000,000 with at most nine decimals; JSON numbers, exponents and digit
separators are refused, and a pricebook needs at least one positive rate.
Endpoints must be HTTPS on port 443 with a qualified host name, no IP literal,
no query and no credentials, and pass the same public-destination,
pinned-resolution and certificate checks as acquisition at connection time.
A credential that is not a single printable header token is denied. The policy
file's parent directories and custody through use remain operator responsibilities;
the final-component guard does not establish a trusted directory tree.

```json
{
  "schema_version": 1,
  "routes": [
    {
      "route_id": "example-eu",
      "adapter": "openai-compatible-chat",
      "endpoint": "https://provider.example.invalid/v1/chat/completions",
      "model": "example-model",
      "credential": {"kind": "systemd", "name": "example-key"},
      "tasks": ["structured_extraction"],
      "data_classes": ["public"],
      "provider": {
        "controlling_jurisdiction": "AT",
        "processing_regions": ["AT"],
        "foreign_legal_exposure": "none",
        "retention_training": "none",
        "evidence_date": "2026-10-01"
      },
      "pricebook": {
        "currency": "EUR",
        "input_per_million": "0.40",
        "output_per_million": "1.20",
        "effective_date": "2026-10-01"
      },
      "cap": "5.00",
      "max_input_chars": 20000,
      "max_output_tokens": 1000,
      "timeout_seconds": 60
    }
  ]
}
```

Provider facts are operator assertions with an evidence date, not verified
by this software. A route conforms only when every fact is known, the
controlling jurisdiction and every processing region are EU/EEA, foreign legal
exposure is `none` and retention/training is `none`. Any `unknown` denies. A
known nonconforming route needs an `exception` with a rationale and the
permitted tasks; its attempts are recorded as `exception`, not as conforming.
EU hosting alone is not conformity. `conforming` is this declared-policy
classification, not verified legal or sovereignty approval. Evidence and pricebook
dates are retained; the implementation does not fetch facts/prices or enforce an
automatic age/expiry rule.

## Credential delivery and compatibility

Prefer `credential` references to a provisioned systemd credential name or a
checked absolute file path. Systemd ACL delivery must grant only the current UID;
a shared evidence group does not authorize credential access. Both use the shared [credential custody contract](api-acquisition.md#credential-custody),
including bounded printable tokens, protected ancestors, no symlinks and private
file modes. `CREDENTIALS_DIRECTORY` selects the systemd directory; it does not
contain a token value. Actual service delivery requires separately provisioned
and tested host configuration; this increment does not install that service.

Exactly one of `credential` or `credential_env` must be configured. The explicit
legacy `credential_env` channel remains supported for compatibility but is
deprecated; new configurations should use references. A missing or unsafe
credential reference fails closed without falling back to an environment value.
A route cannot configure both channels. Changing the channel/reference changes
the exact route identity and does not silently redirect old queued work.
Replacing local credential material does not revoke the old provider token;
rotation includes provider-side revocation and independently tested recovery.

## Running a routed enrichment

```sh
# OW_WRITER_DSN, OW_EVIDENCE_ROOT and credential delivery are configured privately.
osint-workbench enrich enqueue --route example-eu --cloud-policy /etc/ow/cloud.json \
  --document-id DOCUMENT_SHA256 --data-class public
osint-workbench enrich work-once --route example-eu --cloud-policy /etc/ow/cloud.json
osint-workbench cloud-exposure --cloud-policy /etc/ow/cloud.json
```

A job binds the exact route definition; editing the route creates a different
job kind, so old queued jobs are not silently sent under new terms. The local
generator and a remote route never fall back to each other.

## Ledger states and exposure

Before accepting typed provider output, the adapter refuses an exact occurrence
of the active dispatch credential in decoded output strings or keys, including
JSON-escaped values. It reports `REMOTE_CREDENTIAL_REFLECTED` and accepts no
assertions. The complete remote response still records a `completed` attempt,
with its reported usage/estimate or retained reservation; application refusal is
not proof of non-dispatch or zero cost, and the failed job is not blindly replayed.
This is a credential-echo backstop, not arbitrary encoding/secret detection,
zeroization or a substitute for source classification and provider trust.

Each admitted dispatch attempt has an `ow.remote_operations` row committed before
any provider connection; policy denials also get a row:

| Status | Meaning | Counted exposure |
| --- | --- | --- |
| `denied` | Policy, credential, budget or unresolved-prior-attempt refusal; no connection | 0 |
| `reserved` | Worst-case cost reserved, not yet sent | reservation |
| `dispatched` | Committed immediately before sending; a crash leaves it here | reservation |
| `released` | Confirmed not sent: deadline before sending or destination/DNS/TCP/TLS refusal | 0 |
| `completed`, `refused`, `incomplete` | Complete provider response | reservation until separate settlement |
| `failed` | Non-200 or malformed response | reservation until separate settlement |
| `outcome_unknown` | Connection lost or deadline after sending | reservation |
| eligible attempt, settled | Operator assertion bound to provider evidence, or zero for a stale unsent reservation | settled amount |

The reservation assumes one input token per UTF-8 byte of the whole request body
(prompt, schema and framing; byte-level and byte-fallback tokenizers emit at
most one token per byte) plus the route's maximum output tokens at the
declared prices, rounded up. Reported usage counts only when it is possible for
the request: at least one and at most one input token per request byte, and no
more output tokens than the route allows. Otherwise it is recorded as missing
and the reservation stands. Plausible reported usage can reduce the informational estimate
below its reservation, but never admission exposure; these bounds do not verify the provider's usage report or
actual billing. A database trigger enforces the
state machine: reserved to dispatched, dispatched to exactly one outcome, and
nothing after that, and a settled attempt is final. Exposure is per route and
currency across the retained ledger, including earlier policy versions for that
route ID; it is not an account-wide or monthly provider quota. Currencies are
never summed or converted. Estimates are not invoices, and an evidenced
settlement may reveal a cost above the reservation or cap.

Reservation admission explicitly uses Read Committed before acquiring the
per-route-and-currency transaction lock. After waiting, the replay and exposure
queries see the preceding holder's committed attempt, including when the login
or database defaults to Repeatable Read. Other transactions keep their configured
isolation. See [ADR-0044](adr/0044-ledger-integration-boundaries.md).

No attempt is retried automatically. Any unsettled attempt that may have
reached the provider blocks further attempts for the same job, and the
enrichment job fails terminally. Conservative exposure can therefore exhaust a
cap with failed or unknown attempts until an operator settles them.

The request deadline starts before the dispatched row commits. A worker that
stalls past it after that commit records `released` with
`REMOTE_DEADLINE_BEFORE_SEND` and sends nothing. Each transport read and write
is bounded by the deadline. A provider that deliberately throttles how fast it
accepts request bytes can still stretch sending, so settle dispatched attempts
only on provider evidence.

## Settlement

Settlement replaces an estimate with an amount the operator asserts from
provider evidence. It runs under a separate login inheriting `ow_accounting`,
configured privately as `OW_ACCOUNTING_DSN`. That login must not also be a
writer member; the command and the database both refuse it. The group may read
the ledger and write only the settlement columns. It cannot change outcomes or reservations, delete
rows, or read documents. Do not add settlement to MCP.

```sh
# OW_ACCOUNTING_DSN is set privately; the evidence file stays outside Git.
osint-workbench cloud-ledger unsettled [--route example-eu] [--include-estimated]
osint-workbench cloud-ledger settle --attempt-id ATTEMPT_UUID \
  --basis invoice --cost 0.004210000 --currency EUR \
  --evidence /private/provider-invoice-line.pdf \
  --actor operator-id --rationale "Invoice line for the dropped request"
```

`unsettled` lists, oldest first and at most 500 per call, unsettled attempts without reported usage. Add `--include-estimated` to include
completed attempts with reported usage; their admission exposure also remains
the reservation. `in_flight` marks reserved or
dispatched rows changed in the last ten minutes. These may belong to a live
worker and cannot be settled yet.

| Basis | Allowed on | Amount | Evidence |
| --- | --- | --- | --- |
| `invoice`, `usage_export`, `provider_statement` | any attempt except `denied` and `released` | exact decimal string in the attempt currency; may exceed the reservation | required file; only its SHA-256 is stored |
| `not_dispatched` | `reserved` rows only, which provably never sent | `0` | none |

- **Evidence file.** The final component is opened without following a symlink
  and must be a non-empty regular file, with reads bounded at 64 MiB. Its parent
  directories and stability during hashing remain operator responsibilities.
  The tool hashes observed bytes; it does not verify the file's provenance or
  copy/upload its contents.
- **Timestamps.** The database assigns the settlement time and every
  transition time; the writer cannot set either. Owners and superusers can
  bypass the trigger and are outside this contract.
- **Finality.** A settled attempt can never be dispatched or updated again. A
  worker that resumes late gets `INVALID_LEDGER_TRANSITION`.
- **Retries.** Repeating the identical command returns the receipt with
  `replayed: true`. Any changed value fails with `SETTLEMENT_CONFLICT`.
- **Corrections.** There is no edit command. A wrong settlement needs a
  reviewed database change outside this tool.
- **Re-running work.** Settlement lifts the ledger block for that operation but
  does not requeue a failed job. Repeating an identical enqueue returns the
  existing job. A deliberately new `--operation-id` creates a distinct job and
  can incur another charge; it is not an idempotent retry of the old job. No
  command currently resets the old job for replay.

Errors:

| Error | Cause |
| --- | --- |
| `ACCOUNTING_OPERATOR_REQUIRED` | The login lacks `ow_accounting`, or is also a writer member |
| `ATTEMPT_NOT_FOUND` | No attempt with that ID |
| `SETTLEMENT_NOT_REQUIRED` | The attempt is `denied` or `released` |
| `SETTLEMENT_CURRENCY_MISMATCH` | The currency differs from the attempt's |
| `SETTLEMENT_BASIS_INVALID` | `not_dispatched` used on a row that was dispatched |
| `SETTLEMENT_IN_FLIGHT` | The row may belong to a live worker |
| `SETTLEMENT_BUSY` | A worker holds the row lock; retry later |
| `SETTLEMENT_EVIDENCE_INVALID`, `SETTLEMENT_EVIDENCE_UNAVAILABLE` | The evidence file is not a bounded regular file, or cannot be opened |
| `INVALID_SETTLEMENT` | Missing or malformed arguments |
| `SETTLEMENT_REFUSED` | The database rejected the settlement |

Settlements are operator assertions. The software checks authority, scope,
currency, timing and the evidence digest, not what the evidence says.

## Disclosure boundary

The request contains the enrichment prompt: the document title and full text
as untrusted data, and the proposal schema. Dispatch rows store payload digests
and accounting rather than prompt/response bodies. Settlement additionally
retains the operator-supplied actor and rationale as plaintext, including in
checkpoints; keep private provider content out of those fields. Credentials resolve through the selected reference or explicitly configured
legacy environment channel, and are sent only as a bearer header to the configured
origin. Values are excluded from normal diagnostics and ledger fields; this does
not establish resistance to arbitrary provider reflection or process compromise.
Lifecycle retirement and job cancellation do not recall already-admitted or
physically in-flight provider requests, or prove provider-side deletion.
Model output passes the same schema, quotation and review controls as local
generation; remote output is never accepted as fact without review.


Runtime dispatch uses a separate `OW_DISPATCH_DSN` with `ow_dispatcher`, bound to
its exact generator kind in `ow.worker_kinds`; see
[the operational profile](operational-profile.md#runtime-capabilities-and-evidence-allocation).
Provider usage is telemetry. Only evidence-bound settlement under the independent
accounting credential can reduce a dispatched attempt below its reservation.
