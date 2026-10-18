# Scheduled RSS/Atom acquisition

Core schema v5 introduced the private durable schedule. The current supported
layout is core v10 and, when enabled, retrieval-profile v4. Run the explicit
migrations before using the current code. No sources, URLs, network
calls, host timers or model downloads are supplied or enabled by package import.

Provide one canonical private source configuration outside Git. Removing an entry
does not delete or automatically disable its historical source row; explicitly
set `enabled` false when that is the intended operator disposition. Each enabled source may
set `poll_seconds` (60–86400, default 900) independently of its freshness threshold.
A changed interval affects the next completed attempt; it does not override an
already stored due time. URI/profile changes invalidate prior validators and
freshness, and make the resource immediately eligible. Use distinct source IDs
for unrelated logical collections; changing a URI does not delete historical data.

With a scoped `OW_COLLECTOR_DSN` and `OW_EVIDENCE_ROOT` configured privately, invoke:

```sh
osint-workbench collect --config private/sources.json --due-only --max-sources 32
```

This is one tick, suitable for a separately managed external timer. It does not
install or run that timer. It selects unknown/changed resources before already
known due resources and then orders known work by due time/source ID. The cap is
1–128 dispatches per tick, default 32; excess due sources are reported as deferred.
Disabled entries are synchronized without dispatch. Source-level failures produce
bounded per-source results, do not prevent independent attempts, and cause CLI
exit status 1. No URL or raw response header is returned. Empty configuration
remains an unconfigured, zero-dispatch outcome without database access.

The configuration is capped at 8 MiB and 1000 unique sources. Each HTTP request
uses the existing 30 s total network deadline and 10 MiB limit; parsing retains
its separate subprocess limits. A tick processes sources sequentially and has
no whole-tick wall-clock deadline. An external supervisor must bound runtime;
killing it can leave partial accepted items and an interrupted attempt. Per-source
session locks prevent overlapping acceptance across current collectors, but they
are not a global per-host quota or a distributed execution-termination guarantee.

A due attempt durably reserves its next eligible time before dispatch. Consecutive
failed or unconfirmed attempts use `min(86400, poll_seconds * 2^n)` seconds, where
`n` is the previous failure count; success resets the counter and schedules the
next poll after completion. Restart does not reset a committed delay. The next admitted
collector marks abandoned running receipts interrupted. There is no automatic
sleep/retry loop. `collect` without `--due-only` explicitly bypasses due times and
makes an unconditional request, while retaining the same source exclusion lock.
A successful manual refresh resets scheduling to the configured poll interval.
A failed manual refresh preserves any later previously stored due time.
`--max-sources` applies only to `--due-only`; an explicit cap supplied to manual
collection is rejected rather than silently ignored.

## Server-requested retry delays

Final HTTP 429/503 failures may extend the per-source schedule using one
`Retry-After` field. ASCII nonnegative delay-seconds and the three HTTP-date
formats (IMF-fixdate, RFC850, asctime) are supported. The input is bounded at
128 bytes, and duplicate, combined or malformed fields produce
`INVALID_RETRY_AFTER` with ordinary local backoff. Error bodies and raw retry
fields are not retained, returned or logged. Hints on other status codes and
redirect responses are outside this profile; existing redirect handling remains.

The failure transaction uses the database UTC clock and stores the greatest of
its existing reservation, local backoff and the validated hint. Delta seconds
start at failure persistence, conservatively later than response receipt.
HTTP-date remains absolute UTC; the untrusted origin `Date` header is not a clock.
The rolling RFC850 two-digit century interpretation uses application UTC,
including the full instant at the 50-year boundary; clock correctness remains
an assumption.
Workers do not sleep or retry within the tick. Independent due sources can proceed.

A hint can extend eligibility by at most 604800 s (seven days) from persistence.
A longer valid request is capped and reported as `SOURCE_RETRY_AFTER_CAPPED`.
This protects source availability against unbounded remote deferral and **does
not fully honour a larger requested minimum**. It is an explicit local policy,
not a claim of complete HTTP conformance. Zero, past or shorter hints cannot
shorten ordinary backoff or an existing later reservation.

The failed run, source error and deadline commit together. A persistence failure
reports `COLLECTION_STATE_PERSIST_FAILED`; only the earlier local reservation can
then be relied on. A kill between response receipt and that commit can also lose
uncommitted server advice. The next collector reconciles the running receipt as
interrupted; it cannot reconstruct a lost header. Committed advice survives a
collector restart, but restore deliberately clears schedules and disables sources.
Manual refresh, resource identity changes and explicit restore/re-enablement are
operator overrides; this is not a host-wide rate limit or provider quota.
See [ADR-0029](adr/0029-bounded-retry-after-scheduling.md).

Validators are restricted to bounded printable entity tags and canonical IMF-fixdate
Last-Modified values. Unsupported or ambiguous fields fail closed. Entity tags take
precedence. Redirects never receive the configured URI's validators; redirected
responses cannot populate its validator cache. A 304 requires a conditional request
and verified prior raw evidence. It records a successful HTTP-304 run with that
same raw hash and zero new documents. This confirms representation validation,
not correctness of the source or a new acquisition timestamp for historical items.

A partial run never advances validators. It may retain already accepted items.
After any failed or unconfirmed attempt, the next admitted request omits both
validators and requires a full response; an unsolicited 304 fails. This prevents
an origin returning to the previous representation from validating its cached raw
body while leaving partially accepted newer item heads unreconciled. Successful
full acceptance resets this dirty state; prior validators remain private retained
metadata until then, not permission to skip reconciliation.

Under the per-source collector lock, accepting a full representation explicitly
updates the head of each present, non-suppressed item, even when its immutable
document version already exists. A source observed as A, then B, then exactly A
therefore serves A again without duplicating its document or outbox event. Generic
`ingest` replay retains its separate non-rewinding contract. Items absent from a
feed are not deleted or retired: RSS/Atom feeds can be sliding windows. Partial
acceptance remains visible and is recorded as partial/failure until a later full
attempt completes; this is not an atomic feed replacement or proof of source
truth. See [ADR-0024](adr/0024-observed-source-reconciliation.md).

A feed body is a container. When it changes, an item whose identity recomputed
inside its current head's container equals that head is unchanged: the head is
kept and no snapshot, document or outbox job is created. A successfully accepted
representation remains referenced by its run even if every item is reused or
suppressed. A failure before an item or final run commit can leave no run-level
body reference; parse failures happen before raw-object publication. This is not
an archive of every HTTP response. Returning to older item content inside a
new container is a change from the current head and is recorded as a new
version. Core v8 grants the collector only the digests needed for this
comparison; see [ADR-0040](adr/0040-feed-item-version-reuse.md).

Missing local cached evidence causes an unconditional fetch. Corrupt immutable files require explicit investigation;
network re-fetch does not silently overwrite them. A missing prior object must
be recovered with its exact hash before either scheduled or manual refresh can
report success. A different new body does not clear that observed archive gap;
the prior validator/pointer and failure remain for operator recovery.

The state contains potentially sensitive validators, URI/profile fingerprints
and raw-body references. Readers/MCP cannot select it; reader identity validation
also rejects accidental column grants. Checkpoints remain private and include
those references. Restore clears the cache/schedule and disables sources. Exact
core-v4 format-2 checkpoints can adopt the current layout with an empty schedule
and unknown historical HTTP status, subject to the supported core/profile pair
and all policy/hash/target checks in [recovery](recovery.md).
Core-v3/format-1 adoption remains unavailable.

Remaining acquisition work includes redirect-response retry advice, shared-host rate limits,
jitter, durable cursors, conditional article fetches and additional formats. Real
public-DNS/public-PKI interoperability, production timer cadence and larger-corpus operation
need separate evidence. Synthetic installed-service/timer results are recorded
separately in the collector deployment receipt. See ADR-0023 and the implementation backlog.

The native acceptance suite also routes a disposable local HTTP server through
the real socket/framing/parser/database path. Fixture routing does not establish
public DNS, TLS or address-policy interoperability.

CLI acquisition requires the dedicated collector identity after core migration 6.
The startup check rejects broadened or missing application privileges before
creating an evidence store or dispatching HTTP. `OW_WRITER_DSN` remains for trusted
import/worker code; it is not a collection fallback. An empty source list still
returns `unconfigured` without connecting. See [ADR-0027](adr/0027-collector-database-authority.md).

## Transport trust and resolver limits

Transport failures use the installed HTTP library's documented exception families
and return bounded `SOURCE_UNAVAILABLE`/deadline errors. An explicit URL port zero
is invalid; only configured/default ports 80 and 443 are admitted. HTTPS retains
the original origin for hostname verification, SNI and HTTP Host while TCP uses
a validated numeric DNS answer. Certificate verification remains enabled.

Resolver IPC uses bounded JSON rather than received pickle data. A result may
contain at most 64 addresses, 64 ASCII characters per address and 4096 packet
bytes. The entire answer must be valid/public; excessive sets fail rather than
being truncated. An owned receiver thread lets the same absolute deadline cover
a complete message, including partial frames. Cleanup terminates/joins the owned
resolver and receiver and reports unconfirmed cleanup explicitly. Startup and up
to three one-second cleanup joins are additional overhead; libc/NSS allocations
before the returned Python result are outside these message limits.

Native TLS fixtures use ephemeral authored certificates, add their CA only to a
test context, and route TCP only to loopback. They exercise real TLS, framing,
parser and scoped collector state without changing system trust or claiming live
public DNS/CA compatibility, revocation or deployed TLS acceptance. The separate
supervised service fixture uses synthetic HTTP; it must not be relabelled as a
TLS deployment. See [ADR-0030](adr/0030-native-transport-trust-verification.md).
