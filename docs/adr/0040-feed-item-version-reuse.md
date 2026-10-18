# ADR-0040: Reuse unchanged feed item versions with minimal collector authority

Status: ACCEPTED for the bounded collector. Date: 2026-10-18.

## Context and decision drivers

A snapshot identity binds the source, the raw response digest, the item text
digest and the extractor; a document identity binds that snapshot plus the
item title and publication time. For RSS/Atom collection the raw response is
the whole feed. Any change to the container, including one new entry or a
volatile channel timestamp, therefore gave every unchanged item a new snapshot,
document, current head and `document.accepted` outbox job. ADR-0024 explicitly
rejected a new version identity for every acquisition, yet this was its effect
for every feed revision. A source with N items polled after each container
change produced N redundant immutable versions and N downstream jobs, growing
storage, the full-text index, retention scope and enrichment/embedding queues
without any change in item content. Reader search hid the duplicates because it
reads current heads, so run receipts and searches did not reveal the cost.

The collector runs under the column-scoped `ow_collector` role (ADR-0027). It
could not read the snapshot or document columns needed to compare content.

## Alternatives, including no change

- Keep the current identity. This preserves code and grants but retains
  unbounded amplification on ordinary feed churn and contradicts ADR-0024.
- Remove the raw digest from item identity. This changes every future document
  ID, breaks equality with retained versions and loses the container provenance
  link; it requires a broad identity migration and ADR-0006 revision.
- Look up any earlier version with equal title, text digest, date and extractor.
  This needs SELECT on titles, publication times and text digests for every
  document, widening the hostile-input collector's read authority.
- Compare only against the current head by recomputing the item's identity in
  the head's own container. Equal document IDs prove equal source, key, text,
  extractor, title and publication time. This needs only the head's snapshot ID
  and that snapshot's raw digest. This is the chosen correction.

## Decision and authority boundary

Under the existing per-source collector lock and lifecycle admission,
`Database.ingest_stored(..., observed_current=True)` resolves the item's current
head and its container digest. If the head came from a different container and
recomputing the incoming item's identity with that container yields the head's
document ID, the item is unchanged: the head is kept, and no snapshot, document,
head change or outbox job is written. Otherwise the existing path applies
unchanged, including ADR-0024 reconciliation to an exactly retained earlier
version. Generic `ingest` and replay semantics are unchanged.

Additive core migration 8 grants `ow_collector` SELECT on `documents.snapshot_id`
and on `snapshots(snapshot_id,raw_sha256)`. The collector still cannot read
titles, bodies, text digests, derived records or job state. It can now map any
document version, across sources, to its snapshot and that snapshot's container
digest. These are hashes only, but they let the collector test whether a known
container produced a known version; its own collection state already exposed
the latest container digest per source. The exact
collector grant allowlist and migration-history checks include the new grants.
Exact published core7/profile3 checkpoints are adopted under the existing
independent current-policy restore checks; no table layout changes.

Reuse compares only with the current head. If an item changes and later returns
to earlier content inside a different container, that is a change from the
current head and a new immutable version is recorded. A byte-identical earlier
container reconciles an item to its retained earlier version per ADR-0024 only
when that item's content differs from the current head; content equal to the
head keeps the head, even if an older version from that exact container exists.
This narrows ADR-0024's exact-A rule to items whose content actually changed. Every
fetched container remains retained and referenced by its run record, so GC and
recovery keep the raw evidence. The run's accepted count still counts observed
current items, not newly created versions.

## Consequences, blast radius and reversibility

Unchanged items no longer create redundant versions or jobs. A container change
therefore no longer re-enqueues downstream work for an unchanged item whose
earlier job failed or never ran; that work must be resubmitted explicitly. Search, MCP reads,
lifecycle and purge contracts are unchanged; an unchanged item's evidence span
continues to reference the container in which it was first accepted. A trusted
writer can still bypass cooperative locks through direct SQL; this is
application authority, not row isolation.

Stop collectors before upgrading binaries, then apply migration 8 and re-run
collector validation. An older binary refuses the newer history; reverting the
code requires restoring a compatible database/object/policy set rather than
removing the migration. Reverting only the code restores amplification without
data loss. Existing redundant versions remain retained history; this decision
does not purge or merge them.

## Discriminating verification

Native tests collect a two-item feed, then a changed container with one revised
and one new item, through both the writer and the validated scoped collector
identity. They assert reused identity for the unchanged item, exactly two new
versions and jobs, two retained container digests, reader-visible current heads,
a recorded change on return to older content in a new container and no new
version when an earlier container repeats current content. Collector allowlist,
future-history refusal and exact core7 checkpoint adoption are tested
separately. These are execution contracts, not public-source acceptance.
