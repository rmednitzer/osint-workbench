# ADR-0024: Separate observed source reconciliation from immutable replay

Status: ACCEPTED for the bounded collector. Date: 2026-10-17.

## Context and decision drivers

Generic ingestion deliberately deduplicates an immutable version without moving
the current head backwards when that version is replayed. This protects retries
from overwriting a later accepted version. A serialized collector has additional
information: a newly fetched full representation is the source observation it is
accepting now. Reusing the generic replay rule for this observation leaves the
head at B when a source changes from A to B and returns to byte-identical A.

Partial collection adds a second case. A completed A can be followed by a B that
accepts one item and fails later. If the origin returns to A, a conditional 304
against A's retained validator does not reconcile the partially accepted B heads.
The decision must preserve immutable deduplication, generic retry semantics,
explicit partial outcomes and independent lifecycle suppression.

## Alternatives, including no change

- Keep insertion-monotonic heads everywhere. This preserves replay behaviour but
  cannot represent a source's return to an already retained version accurately.
- Move heads on every generic replay. This fixes collection but grants every
  retry authority to rewind newer work and violates the existing replay contract.
- Add a new version identity for every acquisition. This records observations
  explicitly but duplicates immutable versions and expands schema, derivative and
  recovery scope beyond the required correction.
- Give serialized collection explicit observed-current authority while retaining
  the generic default. This is the chosen bounded correction.

## Decision and authority boundary

`Database.ingest_stored(..., observed_current=True)` may upsert a present item's
head even when its document already exists. The collector supplies this flag
under its existing per-source session lock and cooperative lifecycle admission.
Generic `ingest` and ordinary `ingest_stored` retain the default `False`.
Outbox creation remains conditional on insertion of a new immutable document.
Retention/retirement checks still apply before acceptance; the flag cannot revive
a suppressed logical item.

After a failed or unconfirmed attempt, the collector sends no HTTP validator and
requires a full response. Successful complete acceptance clears the failure
counter and permits later conditional requests. Old validators are retained until
then as private recovery metadata; an unsolicited 304 is an acquisition failure.

This is application authority, not a new SQL privilege boundary. A trusted writer
can bypass cooperative locks through direct SQL or other ingestion paths; this
change does not contain such an actor. A feed's omission of an older item does
not authorize deletion, retirement or a claim that the complete source corpus has
been replaced. Already committed partial items remain visible; whole-feed atomic
replacement is outside this decision.

## Consequences, blast radius and reversibility

A source can reactivate a retained document version without duplicate jobs.
Consumers must still enforce current-head and lifecycle dependency checks; no new
semantic review, index quality, factual currency or production readiness is
established. Dirty attempts transfer the full body, trading bandwidth for a
recoverable acceptance boundary. Historical versions and run receipts remain
unchanged. No migration, implicit collection, original-environment mutation or
physical deletion is introduced.

Stop external collection triggers before changing collector binaries. Reverting
the code preserves retained data and generic replay semantics but loses this
source-reconciliation guarantee. Do not present an older binary as equivalent
acceptance, or roll schema/policy backwards to clear a failed run. Recovery uses
the compatible isolated-target and independent-policy procedure.

## Discriminating verification

`tests/test_source_reconciliation.py` exercises real PostgreSQL heads, reader
searches, run/failure metadata and outbox counts for A/B/exact-A, partial B/full A,
and dirty unsolicited 304. The retained generic replay regression separately
asserts that replaying A after B does not rewind the generic head. Native tests
must pass against the installed candidate wheel; unavailable local PostgreSQL is
recorded as unverified rather than a pass. These fixtures establish execution
contracts, not public-source or model quality.

> Successor note (2026-10-18): [ADR-0040](0040-feed-item-version-reuse.md) keeps the current head for items unchanged inside a changed feed container. The A/B/exact-A and partial-B cases above are unchanged.
