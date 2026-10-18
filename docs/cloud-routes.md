# Governed remote routes

> Bounded contract slice. See [ADR-0042](adr/0042-governed-compatible-cloud-route.md),
> [ADR-0043](adr/0043-remote-attempt-settlement.md) and STATUS for verified scope.
> Native vendor adapters, streaming, batches, invoice import and live-provider
> acceptance are not implemented.

Remote generation is off unless all of the following hold: an operator policy
file outside Git, a route in it, the route's credential in the environment, an
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
A credential that is not a single printable header token is denied.

```json
{
  "schema_version": 1,
  "routes": [
    {
      "route_id": "example-eu",
      "adapter": "openai-compatible-chat",
      "endpoint": "https://provider.example.invalid/v1/chat/completions",
      "model": "example-model",
      "credential_env": "OW_ROUTE_EXAMPLE_KEY",
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
EU hosting alone is not conformity.

## Running a routed enrichment

```sh
# OW_WRITER_DSN, OW_EVIDENCE_ROOT and the route credential are set privately.
osint-workbench enrich enqueue --route example-eu --cloud-policy /etc/ow/cloud.json \
  --document-id DOCUMENT_SHA256 --data-class public
osint-workbench enrich work-once --route example-eu --cloud-policy /etc/ow/cloud.json
osint-workbench cloud-exposure --cloud-policy /etc/ow/cloud.json
```

A job binds the exact route definition; editing the route creates a different
job kind, so old queued jobs are not silently sent under new terms. The local
generator and a remote route never fall back to each other.

## Ledger states and exposure

Each attempt is one `ow.remote_operations` row, written before any connection:

| Status | Meaning | Counted exposure |
| --- | --- | --- |
| `denied` | Policy, credential, budget or unresolved-prior-attempt refusal; no connection | 0 |
| `reserved` | Worst-case cost reserved, not yet sent | reservation |
| `dispatched` | Committed immediately before sending; a crash leaves it here | reservation |
| `released` | Connection or TLS setup failed; no request bytes were sent | 0 |
| `completed`, `refused`, `incomplete` | Complete provider response | estimated cost if usage was reported, else reservation |
| `failed` | Non-200 or malformed response | reservation unless usage was reported |
| `outcome_unknown` | Connection lost or deadline after sending | reservation |
| any of the above, settled | Operator settlement with provider evidence | settled amount |

The reservation assumes one input token per UTF-8 byte of the whole request body
(prompt, schema and framing; byte-level and byte-fallback tokenizers emit at
most one token per byte) plus the route's maximum output tokens at the
declared prices, rounded up. Reported usage counts only when it is possible for
the request: at least one and at most one input token per request byte, and no
more output tokens than the route allows. Otherwise it is recorded as missing
and the reservation stands, so a reported estimate never exceeds or undercuts
its reservation through implausible numbers. A database trigger enforces the
state machine: reserved to dispatched, dispatched to exactly one outcome, and
nothing after that, and a settled attempt is final. Exposure is per route and
currency and is never summed across currencies or converted. Estimates are not
invoices.

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
writer member; the command and the database both refuse it. The group may read the ledger and write
only the settlement columns. It cannot change outcomes or reservations, delete
rows, or read documents. Do not add settlement to MCP.

```sh
# OW_ACCOUNTING_DSN is set privately; the evidence file stays outside Git.
osint-workbench cloud-ledger unsettled [--route example-eu] [--include-estimated]
osint-workbench cloud-ledger settle --attempt-id ATTEMPT_UUID \
  --basis invoice --cost 0.004210000 --currency EUR \
  --evidence /private/provider-invoice-line.pdf \
  --actor operator-id --rationale "Invoice line for the dropped request"
```

`unsettled` lists, oldest first and at most 500 per call, the attempts whose
exposure is still the reservation. Add `--include-estimated` to include
completed attempts with reported usage. `in_flight` marks reserved or
dispatched rows changed in the last ten minutes. These may belong to a live
worker and cannot be settled yet.

| Basis | Allowed on | Amount | Evidence |
| --- | --- | --- | --- |
| `invoice`, `usage_export`, `provider_statement` | any attempt except `denied` and `released` | exact decimal string in the attempt currency; may exceed the reservation | required file; only its SHA-256 is stored |
| `not_dispatched` | `reserved` rows only, which provably never sent | `0` | none |

- **Evidence file.** It is read without following symlinks, must be a
  non-empty regular file of at most 64 MiB, and is never copied or uploaded.
- **Timestamps.** The database assigns the settlement time and every
  transition time; the writer cannot set either. Owners and superusers can
  bypass the trigger and are outside this contract.
- **Finality.** A settled attempt can never be dispatched or updated again. A
  worker that resumes late gets `INVALID_LEDGER_TRANSITION`.
- **Retries.** Repeating the identical command returns the receipt with
  `replayed: true`. Any changed value fails with `SETTLEMENT_CONFLICT`.
- **Corrections.** There is no edit command. A wrong settlement needs a
  reviewed database change outside this tool.
- **Re-running the job.** Settling an attempt lifts the replay block for its
  operation. To run the work again, enqueue it again; nothing is retried
  automatically.

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
as untrusted data, and the proposal schema. Rows store only digests and
accounting. Credentials are read from the named environment variable, sent
only as a bearer header to the configured origin and never stored or logged.
Model output passes the same schema, quotation and review controls as local
generation; remote output is never accepted as fact without review.
