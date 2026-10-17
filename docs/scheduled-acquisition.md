# Scheduled RSS/Atom acquisition

Core schema v5 adds a private durable schedule; retrieval-profile v2 is unchanged.
Run the explicit migration before using this version. No sources, URLs, network
calls, host timers or model downloads are supplied or enabled by package import.

Provide one canonical private source configuration outside Git. Removing an entry
does not delete or automatically disable its historical source row; explicitly
set `enabled` false when that is the intended operator disposition. Each enabled source may
set `poll_seconds` (60–86400, default 900) independently of its freshness threshold.
A changed interval affects the next completed attempt; it does not override an
already stored due time. URI/profile changes invalidate prior validators and
freshness, and make the resource immediately eligible. Use distinct source IDs
for unrelated logical collections; changing a URI does not delete historical data.

With `OW_WRITER_DSN` and `OW_EVIDENCE_ROOT` configured privately, invoke:

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
next poll after completion. Restart does not reset the delay. The next admitted
collector marks abandoned running receipts interrupted. There is no automatic
sleep/retry loop. `collect` without `--due-only` explicitly bypasses due times and
makes an unconditional request, while retaining the same source exclusion lock.
`--max-sources` applies only to `--due-only`; an explicit cap supplied to manual
collection is rejected rather than silently ignored.

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

Missing local cached evidence causes an unconditional fetch. Corrupt immutable files require explicit investigation;
network re-fetch does not silently overwrite them. A missing prior object must
be recovered with its exact hash before either scheduled or manual refresh can
report success. A different new body does not clear that observed archive gap;
the prior validator/pointer and failure remain for operator recovery.

The state contains potentially sensitive validators, URI/profile fingerprints
and raw-body references. Readers/MCP cannot select it; reader identity validation
also rejects accidental column grants. Checkpoints remain private and include
those references. Restore clears the cache/schedule and disables sources. Exact
core-v4 format-2 checkpoints can adopt the v5 layout with an empty schedule and
unknown historical HTTP status, subject to all existing policy/hash/target checks.
Core-v3/format-1 adoption remains unavailable.

Remaining acquisition work includes Retry-After policy, shared-host rate limits,
jitter, durable cursors, conditional article fetches and additional formats. Real
DNS/TLS adversarial cases, deployed timer behaviour and larger-corpus operation
need separate evidence. See ADR-0023 and the implementation backlog.

The native acceptance suite also routes a disposable local HTTP server through
the real socket/framing/parser/database path. Fixture routing does not establish
public DNS, TLS or address-policy interoperability.
