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

## Corrected after the first increment

| Finding | Observed behaviour | Correction | Discriminating test |
| --- | --- | --- | --- |
| One unencodable document fails every index build | A zero-width-only feed entry, a document over 200,000 code points, or other content-determined encoder refusal failed the whole generation; semantic maintenance stayed blocked until the document was retired | Retrieval-profile migration 4 records such refusals as explicit member exclusions with a fixed reason; runtime failures and a majority-excluded corpus still fail; coverage is reported ([ADR-0041](../adr/0041-explicit-retrieval-exclusions.md)) | `test_content_refusals_become_explicit_exclusions_not_build_failures`, `test_majority_exclusion_and_runtime_failures_still_fail_the_build`, `test_purge_removes_an_excluded_member_and_records_its_count` |

## Integration incident

The PR #9 merge commit `e594e949` took its message from a PR description that
ended with attribution and session URLs. The required new-commit metadata scan
correctly reported `unclassified-url` on `main`, and the dependent build
attestation was skipped for that commit; every branch commit had passed the
scan. The history was not rewritten. Later publication policy excludes private
session/attribution links and preflights the explicit intended commit/merge
message; approved public technical references remain allowed. Incremental scans
cover only their selected base-to-head range and do not clear the historical message.

## Open, with rationale

The subsequent review of merged PRs #9–#12 found two integration defects:
populated `remote_operations` rows were missing a purge inventory key, and
reservation locks did not refresh Repeatable Read snapshots. The successor
corrections and native acceptance cases are specified in
[ADR-0044](../adr/0044-ledger-integration-boundaries.md). Their merged source
`d01f80ac88da50c9f826b1a15cb18c75bd1db75f` completed
[foundation run 39133727926](https://github.com/rmednitzer/osint-workbench/actions/runs/39133727926)
successfully; the preceding PR #13 run reported 1031 passes with no skips in each
of three installed/native profiles. That acceptance is bounded to the named
source and cases, not complete cloud/batch/recovery programme closure. Earlier migration bytes, grants and public history remain
unchanged. A full-range scan from `a5251478` still identifies the historical
`e594e949` message; the planned-message preflight does not clear that finding.

| Finding | Severity | Disposition |
| --- | --- | --- |
| Enrichment subject/object are not required to occur in the quoted span, yet are labelled source mentions | Medium | Needs a decision between span-bound mention validation and renaming the field contract; affects model-output acceptance and existing assertions |
| Writer role can self-review its own enrichment proposals | Low-Medium | Documented as attribution, not authentication; needs a separate reviewer role and migration |
| MCP 64 KiB result cap is reachable inside advertised schema maxima (search/briefing/assertion pages) | Low-Medium | Needs size-aware pagination or lower schema maxima |
| `parse_special` applies to embedded source text in local generation prompts | Low-Medium | Tokenize manifest template separately from untrusted text |
| Retrieval writer has whole-row UPDATE on generations/active pointer | Low | Additive retrieval-profile migration narrowing to status/error columns |
| `enqueue` on terminal job returns old ID; lock wait surfaces raw `LockNotAvailable` | Low | Return status explicitly; map lock timeout |
| `document_heads` not bound to its key by a composite FK | Low | Hardening migration; no tenancy claim exists |
| Reader validation is a denylist | Low | Exact allowlist like collector validation |
| Migration digests use text in some paths and bytes in recovery | Low | Unify on bytes with a CRLF regression |
| Non-canonical ETag/Last-Modified fails an otherwise valid fetch | Design | Matches documented fail-closed contract; availability trade-off retained |

The review at the source above did not identify additional defects in the tested
boundaries for SSRF/rebinding address enforcement and per-hop
re-resolution, decompression refusal, XXE/entity/depth parser isolation,
Retry-After parsing, stale-validator reset on URL change, lease fencing and
cancellation, migration locking, SQL parameterization, MCP tool surface and
error redaction, chunk coordinates, embedding identity, activation atomicity
and RRF determinism. See the PR description for the per-area evidence summary.

## Operational-profile successor

[ADR-0045](../adr/0045-bounded-operational-profile.md) adds serialized-byte MCP
pagination, literal source/trusted-template tokenization with a new generator
identity policy, and exact effective reader relation/column validation. The table
above records the original review, not a floating current disposition. The
successor's installed/native regressions and service results must be tied to
their tested revision in STATUS; their existence alone is not a pass.
Independent reviewer authority, label/quote semantics, retrieval writer grants,
terminal-job retry behavior and other listed findings remain separate work.

## Label-contract successor (2026-10-19)

The historical label/quote finding above is addressed by the explicit read-API
rename in [ADR-0051](../adr/0051-honest-assertion-label-bindings.md), rather than
requiring literal normalized labels in quotations. V2 reports no entity
resolution and exposes label-binding IDs. This closes the misleading naming
contract only; it does not establish label-specific coordinates, entailment or
independent reviewer authority. Historical test outcomes above are unchanged;
current verification must name the successor revision.

## Reviewer and retrieval authority successor

[ADR-0053](../adr/0053-reviewer-database-authority.md) implements separate SQL review
credentials, explicit historical requalification and retrieval profile 5 column
UPDATE grants. Candidate installed verification belongs to its exact PR revision;
earlier outcomes above do not validate the successor. Human independence, adopted
semantic quality and broader producer separation remain open.
