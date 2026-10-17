# ADR-0029: Persist bounded per-source Retry-After scheduling

Status: ACCEPTED for the bounded acquisition profile. Date: 2026-10-17.

## Context and protocol basis

The collector already reserves a durable per-source next attempt and uses bounded
exponential failure backoff. Ignoring an origin's temporary-unavailability or
rate-limit advice can retry unnecessarily; sleeping inside the collector would
hold resources and delay independent sources instead of preserving a scheduling
decision across restart. Response metadata is untrusted and cannot authorize
unbounded work, indefinite resource ownership or disclosure through diagnostics.

[RFC 9110 section 10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3)
defines Retry-After as an HTTP-date or nonnegative decimal seconds. For 503 it
describes the expected unavailability; for redirects it describes a requested
minimum before following the redirect.
[RFC 6585 section 4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4)
allows a 429 response to supply Retry-After. This increment handles final 429/503
responses only. Redirect-delay semantics and other response statuses remain
outside the implemented scheduling profile.

## Alternatives, including no change

- Keep local backoff only. This avoids a new parser but ignores usable server
  guidance even when it fits existing durable scheduling.
- Sleep before retrying in the worker. This retains a process/connection and
  delays other sources, loses timing authority on restart and creates avoidable
  cancellation ambiguity; reject it.
- Accept arbitrary supplied delays without a bound. This honours very long
  requests but lets hostile or erroneous metadata suppress a source for an
  effectively indefinite period or exceed time/integer representations.
- Reject every oversized request and retain ordinary backoff. This makes limits
  visible but can retry substantially earlier than a large legitimate request.
- Persist a seven-day capped deadline, retain a distinct cap disposition and
  document the deviation. Choose this bounded profile trade-off.

## Decision and numeric limits

For a final 429 or 503, parse at most one bounded Retry-After field into typed
scheduling data. Accept unsigned ASCII decimal delta-seconds and supported HTTP
date forms; do not split a date's comma as a list separator. Duplicate, malformed
or unsupported input produces `INVALID_RETRY_AFTER` and no delay beyond ordinary
failure backoff. An absent field retains `SOURCE_HTTP_ERROR`. No raw header,
response body, configured URL or exception text enters the public error result.
Acquisition fails; no feed documents are accepted from the error response.

`MAX_RETRY_AFTER_SECONDS` is 604800, exactly seven days. A valid requested delay
beyond that horizon is capped and reported as `SOURCE_RETRY_AFTER_CAPPED`.
This is a deliberate local scheduling limit, not full honouring of a larger
server-requested minimum. A legitimate source may remain unavailable beyond the
cap and receive another request then. Operators requiring stricter politeness or
long preservation of an origin's minimum must leave that source disabled until
its independently reviewed re-enablement; this profile does not silently promise
that stronger policy.

The database clock supplies the scheduling reference. For delta-seconds, add the
validated delay to database failure-recording time: this conservatively waits at
least that duration after response receipt when the clocks are stable. For an
absolute date, compare the UTC timestamp with the database clock, treating a past
deadline as no additional delay and capping a future deadline to seven days from
that reference. Use the maximum of the existing attempt reservation, ordinary
failure-backoff deadline and bounded server deadline. Zero seconds or a past date
cannot shorten local backoff. Do not sleep or retry within the worker.

The failure transaction records the new `next_attempt`, run failure and bounded
source error together. Preserve the failure counter and last completed validators;
the next admitted attempt still requires unconditional full reconciliation after
failed/unconfirmed work. Existing collection-run HTTP status remains NULL for
these failures; its published constraint accepts only successful 200/304 states.
Do not silently expand that column contract to record 429/503.

If that failure/advice transaction cannot be confirmed committed, return
`COLLECTION_STATE_PERSIST_FAILED`; do not return the original retry disposition
as though its schedule were durable. The earlier pre-dispatch local reservation
remains the last confirmed durable decision. The run may still appear running
and be reconciled as interrupted on restart. A connection lost during commit can
leave an unknown outcome; inspect the database rather than assume rollback or
successful persistence. A process crash between receiving advice and committing
it cannot preserve uncommitted server advice. This increment does not journal
every received HTTP error independently of the database transaction.

## Date parsing and clock assumptions

[RFC 9110 section 5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7)
defines IMF-fixdate and the obsolete RFC 850/asctime forms and requires recipients
to accept all three HTTP-date forms. This parser supports those three grammars
defensively rather than accepting arbitrary email date syntax. Two-digit RFC 850
years use a rolling 50-year interpretation against application UTC date/time,
including the date/time boundary comparison. Unsupported representations fail
explicitly; no comprehensive HTTP conformance claim follows from these parser
cases.

The database clock controls durable admission; application UTC resolves the
obsolete two-digit year. Clock skew, discontinuities or an incorrect database
clock can change observed waits. Origin Date/Age headers do not silently replace
the trusted scheduling clock. Monotonic in-process transport deadlines still
bound the current HTTP exchange and are separate from wall-clock retry admission.

## Operator policy, scope and recovery

Automatic due-only ticks respect the persisted timestamp across process restart.
Explicit manual collection deliberately bypasses stored due time, including a
server-derived delay; it is an operator override, not an automatic retry. A new
429/503 from that manual attempt still records its bounded delay for later
automatic ticks. A failed manual attempt preserves an older later reservation;
a successful manual refresh can reset the schedule to its normal poll interval.
Changing resource identity also resets its existing schedule
under the established configuration contract.

The state is per configured source. Multiple source IDs or redirected resources
can share a host without a shared quota or circuit breaker; none is introduced
here. All requests retain existing public-address, redirect and transport bounds.
There is no new migration, credential, MCP mutation, host timer or implicit fetch.
Core/profile versions and checkpoint format remain unchanged.

Checkpoints retain the existing schedule field, but restore deliberately clears
cached HTTP scheduling and disables sources. Explicit restored-source
re-enablement is therefore a scheduling override; do not claim an origin delay
survives restore merely because it survives an ordinary process restart.

## Consequences, blast radius and reversal

Valid server guidance can delay a source beyond local exponential backoff without
occupying a worker or blocking independent sources. Malformed advice remains a
visible acquisition failure with the existing finite retry policy. Seven-day
clamping bounds the effect of untrusted metadata but trades away full compliance
with longer requested waits; the distinct error disposition preserves that
counterargument rather than calling the result fully honoured.

Scope is the extracted application and disposable fixtures. No original source,
endpoint or host is used. Stop collection before binary rollback. Older code may
respect a persisted future `next_attempt` while ignoring fresh Retry-After advice;
do not describe that as equivalent behaviour. Do not erase due state merely to
make a service healthy. A deliberate manual override or compatible isolated
restore remains an explicit operator decision, with current lifecycle policy
preserved. No SQL migration reversal or evidence rewrite is required.

## Discriminating verification

Require independent wire fixtures for 429/503 delta/date advice, zero/past dates,
supported obsolete forms, duplicate/oversized/malformed input and the seven-day
cap. Native PostgreSQL cases must show greater-of-backoff/server admission,
durability through a restarted collector, no early automatic request, independent
source progress, explicit manual override and unchanged validators/no accepted
error-body documents. Demonstrate that transport errors or bad metadata do not
hide source failures or print raw header canaries. Terminate the collector's
database backend while a fixture returns retry advice: the call must report
unconfirmed state persistence, and a restarted collector must honour the last
durable reservation/reconcile the interrupted run. Existing restore and scoped
principal contracts must still pass in the installed wheel.

The [native CI receipt](../testing/verification-evidence.json) and separate
[actual-service receipt](../testing/collector-deployment.json) record the executed
scope on their exact source revision and measured installed wheel. These parser and scheduling cases do not establish shared-host fairness,
external-provider behaviour, clock correctness or complete HTTP conformance.
