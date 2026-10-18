# Governed remote routes

> Bounded contract slice. See [ADR-0042](adr/0042-governed-compatible-cloud-route.md)
> and STATUS for verified scope. Native vendor adapters, streaming, batches,
> reconciliation and live-provider acceptance are not implemented.

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

The reservation assumes one input token per UTF-8 byte of the whole request body
(prompt, schema and framing; byte-level and byte-fallback tokenizers emit at
most one token per byte) plus the route's maximum output tokens at the
declared prices, rounded up. Reported usage counts only when it is possible for
the request: at least one and at most one input token per request byte, and no
more output tokens than the route allows. Otherwise it is recorded as missing
and the reservation stands, so a reported estimate never exceeds or undercuts
its reservation through implausible numbers. A database trigger enforces the
state machine: reserved to dispatched, dispatched to exactly one outcome, and
nothing after that. Exposure is per route and
currency and is never summed across currencies or converted. Estimates are not
invoices.

No attempt is retried automatically. Any attempt that may have reached the
provider blocks further attempts for the same job until reconciled, and the
enrichment job fails terminally. There is no reconciliation command yet: an
operator who has provider evidence must resolve it outside this tool and
enqueue new work with a new `--operation-id`. Conservative exposure can
therefore exhaust a cap with failed or unknown attempts; that is intended.

## Disclosure boundary

The request contains the enrichment prompt: the document title and full text
as untrusted data, and the proposal schema. Rows store only digests and
accounting. Credentials are read from the named environment variable, sent
only as a bearer header to the configured origin and never stored or logged.
Model output passes the same schema, quotation and review controls as local
generation; remote output is never accepted as fact without review.
