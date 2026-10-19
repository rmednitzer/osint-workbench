# ADR-0051: Name assertion label bindings without claiming source mentions

Status: ACCEPTED. Date: 2026-10-19.

## Context and decision criteria

The v1 assertion response called subject/object hashes mention IDs and reported
`source-mentions-only`. Extraction verifies the quotation's original-text span,
but does not require either label to occur there. For example, a quotation can
say storage is unavailable while the proposed object label is availability.
Quotation location and a syntactically valid label do not establish entailment.
The audit identified this mismatch. Criteria are honest machine-readable meaning,
preservation of existing evidence/identities and explicit consumer migration.

## Alternatives

| Option | Consequences |
| --- | --- |
| No change; rely on prose warnings | Keeps misleading machine-readable claims; rejected |
| Require both labels literally inside the quote | Rejects normalized labels without proving semantics; needs separate occurrence/disambiguation and legacy policy; deferred |
| Add aliases but retain mention names | Continues the misleading contract and obscures migration; rejected |
| Version and rename the read projection | Corrects meaning without rewriting stored evidence; selected |

## Decision and compatibility

Assertion reads return `assertion-proposals/2`, `entity_resolution=not-performed`
and `subject_label_binding_id`/`object_label_binding_id`. Remove v1 mention names.
The ordered JSON hash inputs remain document, quotation start/end, role and
label. The stable hash binds the proposal label to quotation context, not its
occurrence, truth, entity identity or unique assertion. The extraction schema,
model prompts, stored rows/reviews, quotation coordinates and briefing identity
are unchanged. Old and new records receive the same projection, including the
same envelope for empty results. No migration or checkpoint adoption is needed.

This is a deliberate read-API break for pre-release consumers. There is no silent
compatibility alias or fallback; consumers must accept v2 and the new keys. The
[bounded read contract](../mcp-read-contract.md#assertion-label-bindings) records
the mapping. Seven MCP tools, selectors and byte-budget pagination are unchanged.
Independent reviewer authority, label-specific spans, alias resolution and held-out
semantic quality remain separate unfinished work.

## Assurance, verification and rollback

STPA SC2/SC4 and U19/C19 apply: a correct quotation or digest must not be rendered
as a source mention or accepted factual conclusion. Unit tests exercise the real
read projection with labels absent from the quote, stable old hash values,
role/document/span/label isolation and empty results. Native integration covers
existing stored proposals and actual SDK stdio serialization. Existing review,
retirement, citation and pagination tests preserve neighbouring behavior.

Blast radius is assertion read output and its documented consumer contract.
There is no grant, schema, dependency, collection, provider or operational-host
change. Roll back via a protected PR deploying the previous wheel and coordinating
consumer version handling; do not rewrite records or describe v1 as validated
mentions. A subsequent stronger span contract requires its own explicit version
and historical-record policy. Test availability and exact source/artifact results
remain separate from this design decision.
