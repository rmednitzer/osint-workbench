# ADR-0042: Govern one declared-compatible cloud route with a reservation ledger

Status: ACCEPTED for the bounded compatible-route slice. Date: 2026-10-18.
Refines the proposed [ADR-0012](0012-cloud-policy.md) and
[ADR-0013](0013-accounting-batch.md); native OpenAI/Anthropic adapters, batches,
streaming and live-provider evidence remain open under those records.

## Context and decision drivers

No remote inference path existed. The backlog requires enforced release policy
and durable accounting before any remote dispatch exists, and the profile
requires denial by default, persisted route and reservation before dispatch,
no silent fallback, Decimal per-currency accounting and no blind replay of
ambiguous paid calls. The project has one real model-backed workflow: local
structured enrichment. A cloud capability is only useful if that workflow can
use it under the same evidence validation and review.

## Alternatives, including no change

- No change. Keeps zero egress but leaves the whole cloud profile as
  specification and gives no tested contract for later adapters.
- Native vendor adapters first. Larger surface, vendor-specific usage
  semantics, and still no policy/ledger to sit behind.
- A provider-agnostic "router" with automatic fallback. Violates the
  no-silent-escalation requirement and widens disclosure on failure.
- One declared-compatible chat-completions adapter behind an explicit policy
  gate and a transactional ledger, used only by explicitly routed enrichment
  jobs. Chosen.

## Decision and authority boundary

An operator-supplied policy file (never in Git) lists routes. Each route names
an HTTPS endpoint, model, the environment variable holding its credential,
allowed tasks and data classes, maximum input/output sizes, a dated Decimal
pricebook and a per-currency hard cap, and dated provider facts: controlling
jurisdiction, processing regions, foreign legal exposure and retention/training
use. A route conforms only when every fact is known and EU/EEA-controlled with
no material foreign exposure and no retention. Any unknown fact denies. A known
nonconforming route needs an explicit exception with a rationale and is
recorded as an exception, never relabelled sovereign.

Remote dispatch happens only for an enrichment job enqueued for that route with
an explicit data classification. Local and remote generators have distinct job
kinds; a local failure never creates remote work, and no route falls back to
another.

Before any network activity a decision row is written: denied (with a reason),
or reserved with the worst-case cost of the bounded request. Reservation takes
a per-route-and-currency transaction lock and refuses when existing exposure
plus the new reservation would exceed the cap. Exposure counts every attempt
that could have cost money: reserved, dispatched and unknown outcomes at their
reservation, completed attempts at their estimated cost when usage was
reported and at the reservation when it was not. Unknown usage is never zero;
currencies are never summed or converted.

The row is marked dispatched and committed before the request is sent. A
complete response is classified: valid structured output, refusal, length
truncation, other HTTP status or malformed body. A connection loss or timeout
after the request may have been accepted is outcome-unknown. No path retries
automatically; an unknown or failed attempt keeps its exposure and the job
fails terminally for operator reconciliation. Valid output then passes the
unchanged proposal validation and human review. Credentials come only from the
environment, are sent only to the configured HTTPS origin through the existing
public-destination, pinned-resolution and certificate-verifying transport, and
never appear in errors, rows or logs.

Core migration 9 adds `ow.remote_operations`. The writer, which runs the
enrichment worker, may insert attempts and update only outcome columns. The
reader has no access. The purger may read it for its exact-authority checks;
purge does not remove accounting rows, which hold digests, not content.

## Consequences, blast radius and reversibility

Remote enrichment becomes possible but stays off without a policy file, a
credential, an explicit route on the job and an explicit data class. The
writer identity now holds provider credentials when it runs routed jobs; a
separate dispatcher identity remains open. Conservative exposure can exhaust a
cap with failed or unknown attempts until an operator reconciles them; no
reconciliation command exists yet. The pricebook is operator-declared and
estimates are not invoices.

Removing a route from the policy stops new dispatch while preserving the
ledger. Reverting the code removes the capability; migration 9 is additive
and its rows remain retained history.

## Discriminating verification

Installed adapter code runs against a synthetic HTTPS provider with
configured fixture trust, through the real transport and real PostgreSQL:
successful structured output reaching enrichment proposals; reported and
missing usage; refusal; truncation; HTTP error; dropped connection after
request; unknown-fact, data-class, task, credential and budget denials with
zero provider connections; concurrent reservations against one cap; separate
currencies; and no second dispatch for a failed job. This is contract
evidence, not live-provider, sovereignty or invoice evidence.
