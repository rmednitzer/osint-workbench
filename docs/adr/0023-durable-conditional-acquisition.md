# ADR-0023: Persist due times and representation-scoped HTTP validators

Status: ACCEPTED for the bounded RSS/Atom profile. Date: 2026-10-17.

## Decision and alternatives

No change leaves scheduling and repeat fetches entirely to an operator. An
in-memory timer/cache loses its state at restart and can acknowledge a partially
accepted feed. A separate scheduler service adds another authority and recovery
boundary. Choose an explicitly invoked, bounded database-backed tick using the
existing per-source session lock and lifecycle barrier. No daemon, host timer or
live collection is installed by this change.

Migration v5 adds private `collection_state` and a successful run's HTTP status.
Published v1–v4 and retrieval v1–v2 migrations remain unchanged. The writer owns
schedule/validator updates; MCP readers receive no new content or mutation tools.
A fingerprint binds the configured URI, extraction profile and request variant.
Operational URLs remain external. Validators are private untrusted metadata.

`collect --due-only` chooses unknown/changed resources first, then the earliest
durable due times. Each tick dispatches at most 32 sources by default, configurable
from 1 to 128. Every source rechecks due time under its session lock. A reserved
attempt increments a bounded failure counter and establishes the next attempt
before external dispatch. Completion resets it; failure/crash retains bounded
exponential backoff. Explicit manual `collect` remains unconditional and bypasses
due times. Disabled sources perform no HTTP dispatch.

Prefer If-None-Match to If-Modified-Since. Limit and validate validator syntax,
reject duplicate fields and mismatched/unsolicited 304 responses, and send no
validators to redirect hops. Redirected full responses do not seed the configured
URI's validators. A 304 is a successful validation of already accepted local raw
evidence, never a new document or proof of factual currency. Lost/corrupt cached
objects force an unconditional attempt; immutable corrupt objects are not repaired
silently. A missing prior body must be recovered with its exact hash before
scheduled or manual refresh can report success; a different new representation
cannot hide the detected archive gap. Advance validators only with successful completion after all entries
have been accepted or explicitly suppressed. After a failed or unconfirmed
attempt, retain the previous completed validator as metadata but do not send it:
require a full representation before conditional validation can resume. Otherwise
a source that returns to its previous representation could send 304 while partial
newer item heads remain active. The serialized collector reconciles heads to
observed existing versions under ADR-0024; generic immutable replay remains
non-rewinding. No feed-absence deletion is inferred.

An explicitly supplied `--max-sources` without `--due-only` is rejected. Manual
collection does not silently disregard a requested dispatch cap.

## Recovery, consequences and evidence

Checkpoint format 2 now records exact core-v5 state. Restore clears validators,
cached-body pointers, failure counters and due times, keeps sources disabled and
still requires independent lifecycle-policy reconciliation. The exact published
core-v4/profile-v2 format-2 table contract can adopt an empty schedule and unknown
historical HTTP status. Other legacy layouts remain rejected. GC/checkpoint
reachability includes every private cached-body pointer, even without a run row.

Blast radius is the extracted repository and disposable fixtures. Roll back the
scheduler by stopping its external trigger; use unconditional collection only
when intentionally overriding the stored delay. Do not run old binaries against
an upgraded database or silently roll the database schema back. Restore into an
isolated compatible target and reconcile current policy before reuse.

Tests use actual HTTP/1.1 framing over an in-memory transport, the real parser,
native local HTTP sockets, PostgreSQL transactions/roles, collector restart and
process death, unsupported row-security refusal, detected archive-gap preservation, partial-run
replay, resource changes, missing cache, bounded fair dispatch, backoff, migration
and isolated recovery. They do not establish public DNS/TLS interoperability,
provider operation, deployed timer reliability or semantic source quality.
The added reconciliation regressions distinguish A/B/A observations, a partially
accepted B followed by full A, and an unsolicited 304 after a dirty attempt.
Their native PostgreSQL result must be read from the candidate's verification
receipt; local collection without that database is not execution evidence.
Server Retry-After, shared-host quotas, jitter, cursors and broader acquisition
formats remain explicit follow-up work; this increment does not close E05/E09–E12.
> Compatibility follow-up (2026-10-17): [ADR-0027](0027-collector-database-authority.md) adds scoped collector authority, [ADR-0029](0029-bounded-retry-after-scheduling.md) implements bounded per-source Retry-After, and [ADR-0032](0032-transactional-retired-record-purge.md) adds core7/profile3 recovery conditions. The v5/profile2 and deferred-scope statements below describe the original acquisition increment.
