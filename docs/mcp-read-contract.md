# Bounded stdio read contract

The server exposes seven reads: `search_documents`, `get_document`,
`get_evidence`, `list_sources`, `pipeline_status`, `list_assertions` and
`get_briefing`. Configured local embedding/reranking may run for search. There
is no model selector, generation, job dispatch, policy mutation or remote listener.
The service login must satisfy the exact application reader relation/column
allowlist and have no reachable alternate role. Unknown effective read grants,
writes, sequences or delegation fail startup. This is not tenancy or protection
against an administrator changing grants after startup.

Each successful tool's serialized JSON text fits 65,536 UTF-8 bytes. The limit
includes keys, metadata and JSON escaping, not merely text characters. Schema
defaults and profile-specific maxima are advertised by `list_tools`. Unsupported
fields and invalid selectors fail before service dispatch.

## Records and continuation

Search/assertion/source pages use `results`; briefings use `items`. They include
`pagination` with `scope`, `returned` and `state`. For continuation, merge
`pagination.next_page` selectors into the original arguments, preserving query,
filters, IDs and other fields. Do not derive the next selector from the requested
limit: byte budgeting can return fewer complete records. `page_offset` for search
and assertions resumes inside a fetched window when the maximum backend offset
has been reached. Always use the returned selectors, including their reset to zero.

| State | Meaning |
| --- | --- |
| `more` | Continue with `next_page` within the stated scope |
| `probe` | Continue to test the next bounded backend window; an empty page is possible |
| `complete` | Exhausted this stated scope; `next_page` is null |
| `window_limit` | Backend candidate/offset limit reached; `next_page` is omitted and corpus exhaustion is not established |

Pages are positional over a live ordered query, not a pinned snapshot. Concurrent
ingestion, review or retirement can change ordering between calls. Clients needing
a stable export require a separate future export contract. Search is limited to
the profile's advertised candidate/offset window: lexical offset 10,000, hybrid
offset 200, reranked offset 32. Limits are not recall or complete-corpus promises.
Source enumeration covers the first 1,000 ordered sources; `complete` means that
bounded scope is exhausted, not that no further configured source exists.

Whole records are retained; no assertion, quote or result row is silently truncated
or skipped by byte budgeting. Hybrid eligibility filtering occurs before backend
pagination: `omitted_candidates` explicitly counts fused IDs absent at the shared
hydration statement. Offsets apply to survivors; omission marks the response
degraded. No extra candidates beyond the bounded pools are fetched.
A single record that cannot fit yields `RESULT_ITEM_TOO_LARGE`.
Other oversized non-page envelopes yield `RESULT_TOO_LARGE`. These fixed errors
do not include source text or exception traces.

`list_sources` now returns a `results`/`pagination` envelope instead of a bare
array. `get_briefing` validates the complete stored product and live cited evidence
before projecting a page. It returns `content_scope=briefing_item_page` and keeps
the original full `briefing_id`; the page's serialized bytes do not hash to that
full product identity. Consumers must follow continuation to reconstruct items.
These are explicit client-visible changes; old clients must adapt.

## Assertion label bindings

`list_assertions` returns `ontology_version=assertion-proposals/2` and
`entity_resolution=not-performed`, including on empty pages. Each row contains
`subject_label_binding_id` and `object_label_binding_id`, replacing v1's
`subject_mention_id` and `object_mention_id`. Consumers must explicitly accept
v2 and use the new field names; there is no v1 alias or negotiation mode.
The seven tools, selectors and pagination contract are unchanged.

The identifiers still hash the same ordered JSON array of document ID,
quotation start/end codepoint offsets, role and proposal label. Renaming does not
change the hash value for unchanged inputs. It identifies a label in quotation
context, not a label-specific occurrence, resolved entity or verified statement.
Labels may be normalized or absent from the quotation. Shared quotation context
does not make the two roles identical; different documents, spans or labels have
different hash inputs. An identical label/role/document/span can be shared by
several assertions, so the binding ID is not a unique assertion ID either.

Existing stored assertions, reviews, briefing IDs and checkpoint formats are
unchanged. Both existing and new records use the v2 read projection. Review
state is still independent of label binding and does not authenticate a separate
reviewer. See [ADR-0051](adr/0051-honest-assertion-label-bindings.md).

## Document text and evidence

`get_document` keeps the document response shape and original integrity/identity
metadata. If the requested text would exceed the byte cap, it returns a shorter
prefix and sets `next_offset` in Unicode codepoints. Continue from that returned
offset with the same document ID. A hash verifies the complete stored body before
the page is produced, not just the returned prefix. It does not verify the truth
of its content. Metadata that cannot fit even with a nonempty text prefix yields
`RESULT_ITEM_TOO_LARGE`.

Evidence, status and returned document content remain explicit disclosures to the
MCP client. Read-only access does not anonymize them. Keep private credentials,
source configuration and writable evidence out of the client process. SDK protocol
tests do not establish compatibility with every independent assistant client.
