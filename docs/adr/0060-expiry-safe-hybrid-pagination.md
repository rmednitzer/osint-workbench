# ADR-0060: Expiry-safe hybrid candidate hydration and pagination

Status: ACCEPTED for the bounded exact hybrid profile. Date: 2026-10-20.
Verification belongs to the exact candidate's installed/native checks.

## Context and criteria

Hybrid search selects up to 100 lexical and 100 semantic document IDs, fuses their
ranks, and previously hydrated each selected page entry in a separate statement.
The lifecycle views evaluate expiry at statement start. Repeatable Read preserves
the data snapshot but does not freeze the database clock. A candidate can therefore
be visible during selection and absent during hydration without a concurrent
policy writer. Expanding that missing row as a result raised a backend error and
failed the entire query.

Search must preserve lifecycle filtering, bounded work, deterministic fused order
and honest pagination. A disappearing candidate must not expose suppressed content
or turn other eligible results into a generic backend failure. Reranking and MCP
byte pagination must retain their existing limits.

## Alternatives

- No change: retains a reachable query-wide failure at the expiry boundary.
- Hydrate directly from unfiltered base tables: bypasses current serving policy;
  rejected.
- Ignore missing rows after slicing the requested page: prevents the exception but
  creates avoidable holes and makes offsets describe ineligible candidates;
  rejected.
- Fuse and hydrate every candidate in one larger SQL ranking query: possible, but
  unnecessarily replaces the independently tested Python fusion contract.
- **Selected:** hydrate the entire bounded fused union in one filtered statement,
  retain eligible rows in original fused order, and then apply offset and limit.

## Decision and affected contract

The lexical and semantic pools remain bounded to 100 each. Fusion retains its
existing scores and deterministic tie order. A single `ow.active_documents` query
hydrates at most 200 candidate IDs. The projection uses SQL `DISTINCT` before
fetching: the active-document view can contain duplicate joined rows when retained
head mappings reuse a document ID. Python-side deduplication alone would not bound
the fetched result. Missing IDs are omitted before page slicing;
no extra candidates are fetched from outside the original pools, and scores are
not recomputed to hide the omission. One statement-time visibility decision now
applies to all hydrated rows.

Hybrid responses add `omitted_candidates`, the number of fused candidates absent
at hydration across the entire bounded union, not merely the returned page. Any
omission makes `degraded` true. Existing corpus drift retains primary reason
`CORPUS_CHANGED`; otherwise omissions use `CANDIDATE_VISIBILITY_CHANGED`. The
count still reports simultaneous omissions when corpus drift takes precedence.
An empty result can be a successful degraded response. `excluded_documents`
continues to describe recorded encoder exclusions, not hydration omissions.

Reranking receives its existing first 32 surviving hybrid candidates and preserves
upstream metadata. MCP still enforces its byte budget and seven-read surface.
Offsets describe eligible fused candidates for this call. Pages remain live queries,
not pinned snapshots; expiry or other allowed state changes between calls may move
results. Hydrated rows are already admitted and may complete after their expiry,
including during reranking, as the lifecycle contract permits. This change does
not establish response-time revocation or recall previously disclosed data.

## Consequences, blast radius and rollback

One SQL statement replaces up to 100 per-page hydration statements. Its result is
bounded by 200 metadata/excerpt rows; no full-body or arbitrary-ID read is added.
Consumers must tolerate the additive count and recognize the new degradation
reason. Existing corpus-drift behavior, scores, registry checks, candidate limits
and generation identity remain intact. No schema, migration, dependency, grant,
model selector or MCP tool changes.

Revert the binary through a protected PR; no stored-data reversal is necessary.
An older binary restores the expiry race and the old pagination behavior. Neither
version proves pretrained relevance, complete-corpus recall or operational capacity.

## Verification

Native regressions preconfigure future retention before the read snapshot, select
real SQL candidates, wait for the actual database clock at the fusion/hydration
boundary, and let the installed hydration path evaluate its actual lifecycle view.
They distinguish partial expiry before offset, preserved scores/order, complete
expiry, empty success and corpus-drift reason precedence. Query vectors are
precomputed through the real fixture encoder before arming expiry to isolate this
SQL-clock fault from model startup timing. Existing native inference, registry,
reader-authority, reranker and MCP acceptance remain separate mandatory coverage.
A separate native duplicate-head case observes actual fetched row cardinality,
ensuring deduplication occurs in SQL before Python materialization. Both supported
LTS installed profiles and independent review are required.
