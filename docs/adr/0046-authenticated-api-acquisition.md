# ADR-0046: Bound the first authenticated API acquisition profile

Status: Accepted

## Context and decision criteria

RSS cannot represent authenticated structured APIs or their durable continuation
semantics. The prototype supplies feature intent, not a correctness oracle or
public source catalogue. Commercial intelligence may impose rights that current
shared readers/storage do not enforce. The first increment must establish bounded
transport, credential custody, explicit partial outcomes and restart-safe progress
without implying licensed-provider support or introducing chargeable replay.

## Alternatives

| Option | Consequences |
| --- | --- |
| Keep RSS only | No new authority or migration, but no authenticated structured acquisition |
| Embed arbitrary provider SDKs | Broad hidden retry/auth/telemetry and destination behaviour; provider-specific trust boundaries before a shared contract |
| Store cursors in local files | Avoids SQL changes but separates accepted documents from progress and complicates recovery/concurrency |
| Add bounded SQL page state and a narrow JSON contract | Reuses collector identity, transaction acceptance and recovery with an explicit additive migration |
| Admit restricted content using a descriptive licence field | Records intent without restricting existing consumers; unacceptable enforcement gap |
| Separate rights-domain instances now | Stronger coarse isolation but requires independently provisioned identities/storage and additional adoption evidence; defer restricted ingestion until delivered |

## Decision and interfaces

Implement `bounded-json-pages/1` as HTTPS GET against one operator-configured
query-free endpoint. Refuse redirects and compressed content. Continuation values
are data encoded only as a cursor parameter at that endpoint. Preserve public
address validation, pinned resolution, TLS identity and bounded request/parser
resources. Authentication is none, bearer or one of two fixed API-key headers;
values resolve from checked systemd/file references, never response-selected paths
or token environment variables. Parser children receive no credentialed service
environment. Neither parser limits nor file checks create a same-UID sandbox.

Require explicit `all-existing-uses-permitted` and `unmetered` declarations. Reject
other rights/billing profiles; declarations are not independent legal verification.
No Janes adapter, entitlement check, restricted rights-domain isolation or paid
request support is claimed. Source qualification and query-disclosure policy are
separate work. Broader authentication and provider semantics need specific
contracts and tests rather than inferred generic compatibility.

Add core migration 11 to extend private `collection_state` with cursor, canonical
profile hash, cycle page count and hashed continuation history. Grant only
collector SELECT/UPDATE on new columns; keep reader exclusion. Commit accepted
page metadata and continuation together after durable evidence writes. Keep
partial cycles explicit and mark freshness only on terminal acceptance. Bound a
tick to exactly one page, with a network/parser/admission deadline of at most
120 s; filesystem durability, database finalization and failure recording can
extend total wall time. Bound a cycle to 128 pages and reject repeated
continuations across ticks. One durable run retains each page response, including
empty/reused pages; batching pages into a run would lose earlier raw response
references when no new document retains them. A nonterminal page returns partial
and uses the existing failed/API_PARTIAL run vocabulary without refreshing success.
An explicit operator `--restart` clears progress/freshness and makes a new cycle
due; it does not remove accepted history or prove the abandoned cycle complete.
No absence-as-deletion or complete-snapshot claim.

Restore clears API continuation/history and disables sources, including exact
published core 10/retrieval 4 adoption. Retrieval profile 4 and checkpoint format 2
remain unchanged. API source configuration, endpoints and credential references
stay external to public artifacts. No service unit or operational host deployment
is added by this decision.

## Verification and assurance allocation

The [API runbook](../api-acquisition.md) defines the actual page, secret and command
contracts. Extend existing U1/U4/U8/U10/U12 controls rather than declaring the full
STPA programme closed. Use synthetic parser/credential cases and installed native
API transport/database tests for origin-bound auth, denied destinations, malformed
pages, atomic progress, cross-tick loops, restart, partial freshness, reflected
tokens and private restore. Credential diagnostics and publication scans must not
expose values or private paths. Exact reflection checks do not cover arbitrary
encoded secrets. Real provider and service-delivery evidence remain separate.

## Impact, reversibility and rollback

Blast radius is the opt-in collector/configuration path and additive core schema.
Existing published migrations remain immutable; no new dependency, model download,
MCP tool, subscription or live provider is selected. Existing shared consumers
remain unsuitable for narrower content rights.

Stop API invocations before rollback. An older binary is not accepted against
core 11 merely because the SQL change is additive. Restore a separately verified
matching pre-upgrade database/evidence pair, retaining current lifecycle policy
and replay precautions. Do not edit/delete the published migration or simply drop
new columns in place. Revocation and secure credential reprovisioning are separate
operator actions. Data already disclosed to existing readers is not recalled by
code rollback.
