# ADR-0034: Share only in-flight identical embedding queries

Status: implementation candidate; native installed-wheel verification required
before promotion. Date: 2026-10-17.

## Context and alternatives

Concurrent identical queries currently compete for the same local inference
admission. The private prototype demonstrates useful request coalescing, but its
completed-result cache would require additional policy, expiry and identity
controls here. Preserve the optimization without importing that wider lifecycle.

| Alternative | Benefit | Consequence |
| --- | --- | --- |
| No change | No additional shared state | Identical concurrent requests can receive avoidable inference-busy failures |
| Persistent or TTL query cache | Reuses completed inference | Requires explicit custody, byte budgets, invalidation and model-file integrity semantics; not selected in this increment |
| Global/process-wide coalescing | Shares across encoder instances | Needs explicit principal/workspace ownership and lifecycle; not selected |
| Instance-scoped in-flight sharing | Eliminates overlapping duplicate computation without completed retention | Adds bounded synchronization and explicit waiter failure semantics; selected |

## Contract

`LocalEncoder.query` snapshots and validates the complete manifest, validates the
query packet before admission, and keys sharing by the SHA-256 of the exact UTF-8
packet. This includes model/tokenizer expected hashes and paths, templates,
dimensions, numerical contract and runtime settings. Path changes deliberately
do not share, even though the durable encoder identity is path-independent.
Documents/chunks and direct `invoke` calls do not join query flights.

Each encoder instance owns its flights. Do not reuse an instance across unrelated
security scopes; there is no process-global registry or cross-process sharing.
Forked instances explicitly refuse before touching inherited synchronization;
construct a fresh instance in the child. Configuration/model replacement must
use normal operator coordination. Sharing is not an artifact-rotation protocol.

At most eight distinct owners and 32 waiting callers participate per instance.
An excess caller receives `ENCODER_COALESCING_BUSY` without computing. A follower
waits at most 45 seconds and receives `ENCODER_WAIT_TIMEOUT` on expiry. This is a
wait budget, not an end-to-end request SLO. Owners retain existing fail-fast
shared inference admission and the 45-second native subprocess timeout.

One owner executes the ordinary native path, including model/tokenizer byte and
hash verification and numerical result validation. Followers receive separate
list copies of the same accepted vector or the owner's bounded workbench error
code. An unexpected exception or BaseException wakes followers with
`ENCODER_UNAVAILABLE`; it retains no traceback or arbitrary exception message in
shared state. The owner still observes its own exception.

This is owner-snapshot semantics: a follower does not independently rehash the
files at its arrival time. Replacing a file after owner verification does not
invalidate the already verified bytes used for that flight. A native test pauses
after actual child completion, replaces the model, admits a follower and checks
the verified old result for both; the next independent call refuses the tampered
artifact. This does not authorize live model rotation without draining callers.

A follower timeout or interrupted wait releases only its waiter slot. It never
cancels or releases the owner's inference authority. Completion/failure removes
the flight before waking participants; a later request computes and re-verifies
model files. The shared vector survives only in references held by participating
callers. There is no persisted state, completed cache, TTL, query logging or
metric label containing input text. A hash key is not an anonymization claim.

Only query vectors are shared. Database visibility, lifecycle, retrieval
generation and search result materialization remain per-search decisions. This
does not authorize reuse of document results or bypass retired-content filters.

## Impact, reversibility and verification

No SQL migration, dependency, source configuration, provider route or MCP tool
changes. Core-only installations still import without optional ML dependencies.
The blast radius is local query concurrency on a shared encoder instance; this
does not provide fairness across different requests or distributed scheduling.
Rollback to the previous code removes coalescing with no data conversion. Stop
or drain affected callers during code replacement; do not mix live object state
across versions.

`tests/test_query_flights.py` exercises actual threaded ownership, bounded owner
and waiter refusal, timeout without owner cancellation, failure propagation,
retry, result-copy isolation, distinct key/instance isolation and real fork
refusal. The native case coordinates and observes actual subprocess launches,
executes synthetic ONNX inference, checks one computation for four callers, then
tampers with the model and verifies that a later identical query is rejected.
Instrumentation does not replace child execution or fabricate output. Native
installed-wheel CI remains the promotion gate. These are execution/concurrency
oracles, not pretrained semantic quality or throughput benchmarks.
