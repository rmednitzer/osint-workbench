# ADR-0053: Authenticated review credentials and narrow retrieval updates

Status: ACCEPTED for the bounded CLI/SQL profile; candidate verification is subject
to the exact PR checks. This does not establish independent human review.

## Context and decision criteria

Core 11 lets the producing writer append acceptance under any actor string.
Retrieval profile 4 grants table-wide UPDATE on generation metadata and its active
alias. Both exceed their intended responsibilities. The change must preserve
historical evidence, deny direct SQL bypass by runtime writers, retain reader
projections, support exact known checkpoints and keep published migrations intact.

## Alternatives

- No change: preserves compatibility but leaves producers able to accept their
  own statements and rewrite retrieval identities.
- Separate CLI actor labels only: no database authorization boundary.
- Separate credentials while trusting old approvals: smaller upgrade impact but
  lets historical writer acceptance masquerade as the new review policy.
- A complete authenticated human/workspace service: desirable future scope,
  disproportionate to the current single-operator CLI profile.
- **Selected:** additive SQL authority separation with explicit historical
  requalification, and column-scoped retrieval UPDATE.

## Decision and boundaries

Core migration 12 creates the non-login `ow_reviewer` group. A dedicated login
gets SELECT on `current_assertions`, INSERT on the four review input columns and
USAGE on the review identity sequence. The CLI requires `OW_REVIEWER_DSN`, with
no writer fallback. It validates the actual connection's role closure, privileged
attributes, effective ACLs, delegation, ownership and executable definer functions.
Changed identities, unrelated role memberships and broadened grants are refused.

An invoker trigger records the authenticated session principal and database time.
It denies current or session writer membership, including non-inherited role
membership and SET ROLE. Actor/rationale remain attributed operator input.
Owners and superusers can restore preserved rows and already control the schema;
they remain trusted and cannot pass the runtime command's identity validation.
Concurrent administrator grant changes are outside the runtime guarantee.

Historical review rows retain every original field and gain `legacy_writer`
authority with no invented database principal. Effective decisions consider only
authenticated reviewer rows. Old accepted assertions become pending and affected
briefings become stale until a fresh review. Requalification can make an existing
unchanged digest readable again; it does not relabel or remove its old history.
The reader/MCP projection gains no principal, actor or rationale fields.

Retrieval migration 5 permits UPDATE only of generation status/error and the
active generation pointer. It preserves INSERT, activation/rollback and purger
grants. Producers remain trusted to insert new generation content; these ACLs do
not establish semantic correctness or complete producer-role separation.

Checkpoint format 2 remains data-only. Current checkpoints preserve authenticated
provenance as history. Exact admitted core 4–11/profile pairs normalize old reviews
to legacy authority. Core-11 core-only checkpoints can restore into core-only
targets; mixed or unknown histories stay refused. Restore does not create logins
from captured principal names. PostgreSQL names are historical identifiers and
can be renamed/reused; they do not identify an immutable person.

## Consequences, blast radius and recovery

Review automation must provision a separate credential and replace its DSN.
Upgrades deliberately withdraw reliance on legacy approvals. Migrate both core
and the optional retrieval profile during a quiesced maintenance window; see
[the operator procedure](../reviewer-authority.md). Missing/revoked credentials
reduce availability without accepting a review through another authority.

This is a breaking authorization/schema change. No reverse migration or automatic
regrant to the writer is supplied. Keep a matching pre-upgrade database/evidence
checkpoint and current lifecycle policy if reverting the whole installation.
Do not run an older binary against core 12/profile 5 or restore an older policy to
undo a withdrawal. Preserve new review history when planning recovery.

## Verification

Actual installed SQL tests cover restricted credentials, direct writer attempts,
accidental INSERT grants, non-inherited overlap and SET ROLE, broadened PUBLIC and
login grants, revocation on an existing connection, original-row preservation at
core-11 upgrade, current/legacy checkpoint provenance, cited-product withdrawal
and requalification, and private reader projections. Existing real MCP, lifecycle,
purge, native-model and recovery tests use the dedicated reviewer fixture.
Retrieval tests inspect actual column privileges and reject identity updates;
existing build/activation/rollback/purge/recovery suites remain required.

The STPA successor records unsafe self-acceptance, retrospective authority claims,
broadened grants, refused legitimate reviews and mutable retrieval identity.
No held-out quality, human independence, workspace authorization, operational
deployment or full standard-conformance claim follows from these tests.

## Native integration correction

The first installed run found that the purge catalog still expected pre-12 review
columns and rejected the new trigger. The successor includes both provenance
columns in the exact inventory and allows only the named BEFORE INSERT review
trigger; widened events or extra triggers remain refused by negative tests.
Revocation now checks the sequence's catalog namespace/name without resolving a
protected-schema regclass, so a revoked connection reaches the fixed refusal.
No migration bytes or permission grants are relaxed by these corrections.
