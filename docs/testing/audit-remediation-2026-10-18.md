# Audit dispositions 2026-10-18

Bounded read-only review of `a525147841293f100c1756cfadef70ed27741f14`
across acquisition, storage/jobs/recovery, retrieval/inference and
MCP/enrichment. Findings were confirmed against code before any change. This
record lists dispositions; revision-bound pass/fail evidence belongs to the CI
run of the candidate commit, not to this file.

## Corrected in this increment

| Finding | Observed behaviour | Correction | Discriminating test |
| --- | --- | --- | --- |
| Feed item re-versioning | One changed byte in a feed container re-versioned and re-enqueued every unchanged item | Current-head identity reuse with two collector column grants, core migration 8; [ADR-0040](../adr/0040-feed-item-version-reuse.md) | `test_feed_revision_reuses_unchanged_item_versions[writer,collector]` |
| Ambiguous response framing | Repeated `Content-Encoding`/`Location` collapsed last-wins; gzip bytes were accepted as identity | Repeated framing fields fail closed with their existing typed errors | `tests/test_http_response_fields.py` |
| Redirect fragment | A `Location` fragment was rejected as an invalid source URL | Fragment removed before validation; it is never sent on the wire | Same file; TLS-downgrade control retained |
| Non-ASCII redirect | A non-ASCII `Location` was reported as generic `SOURCE_UNAVAILABLE` | Specific `INVALID_REDIRECT` | Same file |
| Site-local IPv6 | Deprecated `fec0::/10` passed the destination filter | Blocked as non-public | Same file |
| Search past build limits | Unattended growth past the reference build bounds made hybrid/reranked search fail with `REFERENCE_CORPUS_LIMIT` | Over-limit corpus is necessarily drifted: search is `degraded`/`CORPUS_CHANGED`; builds and activation still enforce bounds | `test_unattended_growth_past_build_limit_degrades_search_instead_of_failing` |
| Inference child lifetime | A killed parent released one-slot admission while its encoder/reranker child kept computing | Child-set parent-death SIGKILL plus expected-parent check; unbound children refuse work | `tests/test_inference_child_lifetime.py` (actual SIGKILL of an intermediate parent) |
| Child exit labelling | Signal/limit exits were labelled invalid results; a non-zero reranker exit with a non-object result escaped as a raw exception; `ENCODER_RESULT_LIMIT` was masked | Exit status classified before decoding; result shape type-checked | Same file |
| Model-output NUL | A schema-valid claim containing NUL failed at INSERT as a retryable backend fault, rerunning deterministic inference | Rejected as non-retryable `INVALID_MODEL_RESULT` | `test_invalid_models_accept_no_partial_assertions` NUL cases |
| Briefing field binding | A briefing with a recomputed digest could misstate statement, polarity, source or document of a real accepted assertion, or carry malformed items and an inconsistent empty disposition, and still be served | Each item must have the exact item fields, belong to the recorded selection and equal the live accepted assertion projection; degraded/omission state must match; else `BRIEFING_EVIDENCE_MISMATCH` | `test_self_consistent_briefing_cannot_misstate_its_cited_assertion` |

## Open, with rationale

| Finding | Severity | Disposition |
| --- | --- | --- |
| Enrichment subject/object are not required to occur in the quoted span, yet are labelled source mentions | Medium | Needs a decision between span-bound mention validation and renaming the field contract; affects model-output acceptance and existing assertions |
| Writer role can self-review its own enrichment proposals | Low-Medium | Documented as attribution, not authentication; needs a separate reviewer role and migration |
| MCP 64 KiB result cap is reachable inside advertised schema maxima (search/briefing/assertion pages) | Low-Medium | Needs size-aware pagination or lower schema maxima |
| `parse_special` applies to embedded source text in local generation prompts | Low-Medium | Tokenize manifest template separately from untrusted text |
| Retrieval writer has whole-row UPDATE on generations/active pointer | Low | Additive retrieval-profile migration narrowing to status/error columns |
| Blank or tokenizer-erased document fails the whole index build; one long rerank candidate fails the request | Medium | Reachable from hostile feeds: an entry whose text is only `&#8203;` passes extraction and the encoder blank check. Needs an explicit unencodable-member disposition (retrieval-profile migration, since activation requires members to equal the corpus) or a visible-text extraction rule |
| `enqueue` on terminal job returns old ID; lock wait surfaces raw `LockNotAvailable` | Low | Return status explicitly; map lock timeout |
| `document_heads` not bound to its key by a composite FK | Low | Hardening migration; no tenancy claim exists |
| Reader validation is a denylist | Low | Exact allowlist like collector validation |
| Migration digests use text in some paths and bytes in recovery | Low | Unify on bytes with a CRLF regression |
| Non-canonical ETag/Last-Modified fails an otherwise valid fetch | Design | Matches documented fail-closed contract; availability trade-off retained |

Checked and not defects: SSRF/rebinding address enforcement and per-hop
re-resolution, decompression refusal, XXE/entity/depth parser isolation,
Retry-After parsing, stale-validator reset on URL change, lease fencing and
cancellation, migration locking, SQL parameterization, MCP tool surface and
error redaction, chunk coordinates, embedding identity, activation atomicity
and RRF determinism. See the PR description for the per-area evidence summary.
