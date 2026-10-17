# Prototype comparison and implementation lessons

Review date: 2026-10-17. Public baseline:
`122cdaaa4b95a7a03590a2bb75c6437c1e2495f0`.

The existing private prototype remains useful evidence of feature intent and
failure modes. It is not the correctness oracle for this repository. This review
inspected selected current source functions, live PostgreSQL catalog metadata,
and effective service properties. Installed retrieval and evidence Python files
were compared byte-for-byte with the corresponding reviewed source: all 19 pairs
matched. This does not bind every prototype component or prove deployed dependency
integrity. Broad filename/function discovery was followed by bounded reads; it
was not a complete line-by-line review of every discovered file.

No operational source collection, model execution, provider requests, service
changes or database writes were performed. A reviewed regulatory function ran
against synthetic in-memory substitutes, with no database connections or network
calls. No private source catalog, original unit, schema dump, source file, prompt,
operational identifier or data row is included here. Evidence labels below name
reviewed behavior, not public artifacts containing the private implementation.

## Findings that must not be copied

| ID | Observed behavior and evidence | Consequence and required public contract |
| --- | --- | --- |
| PL01 | Regulatory promotion updates articles and merges optional sections before consulting the promoted-run guard. The caller enumerates validated snapshots in ascending retrieval order and commits an `already_promoted` return. A synthetic probe of the reviewed function issued one article update before returning that status. Live catalog inspection found an article text-search trigger, with no separate replay guard on these tables. | Previously promoted content can be rewritten during replay. With multiple snapshots, intermediate commits can expose older content; an older snapshot can change text before a later snapshot fails validation. Claim: reachable implementation defect, not evidence of observed production corruption. Check operation identity and current-generation authority before any derivative write; commit promotion and receipt atomically. |
| PL02 | Procedure observations are unique by target and state hash; conflict handling does nothing. The current-state view selects the latest inserted live observation. The caller emits a transition only when a new observation was inserted, although it updates target-success metadata after a conflict. | An exact A/B/A state sequence cannot insert the second A, so the view can remain at B and the return transition can be omitted. Claim: static source/catalog counterexample; no live transition was induced. Separate immutable state content from observation occurrence and accepted-current pointers. Event identity must include the observation/operation, not just the old/new hash pair. |
| PL03 | Publication reconciliation validates receipt syntax and requires one matching row, but the dossier update matches a reusable slug without binding the supplied artifact identifier or current manifest digest. The inspected table has a unique slug and no user trigger enforcing generation identity. | A retained older receipt can label a newer dossier generation with the older publication commit. File syntax and a one-row update are insufficient. Bind destination, product generation, artifact ID, manifest digest and publish operation; reconcile idempotently and reject stale/conflicting receipts. Receipt authenticity and actual remote commit/content verification require separate evidence. |
| PL04 | Journal-based usage extraction emits zero token counts for failed direct calls and defaults absent advisory counts to zero. Aggregation does preserve an explicit unknown cost state and documents incomplete log coverage. | Preserve those limitations, but never equate missing usage with observed zero usage. Store nullable native dimensions, measurement state and unresolved reservations. A failed or disconnected request can have a chargeable unknown outcome. No claim of invoice discrepancy follows from this review. |
| PL05 | Catalog refresh can return the retained row count after a fetch failure. A successfully parsed object without the expected catalog field is treated as an empty list, which the replacement path accepts. Response size is checked after the HTTP client has materialized the body. | A row count alone does not establish successful refresh; malformed success content can clear retained state, and a post-download size check does not bound acquisition memory. Require an explicit validated envelope, completeness semantics, bounded streaming and separate attempt/success/freshness state. Genuine empty catalogs need an explicit supported contract rather than an unconditional nonempty rule. |
| PL06 | Search code reports per-stage degradation and can return lexical/fusion results after encoder failures. The effective search unit nevertheless requires both encoder services; the inspected service was running. | Application fallback is not evidence of degraded startup availability. A dependency startup failure or explicit dependency stop can prevent that path from being available. Choose strict-profile startup or optional-stage availability deliberately, then test the actual service dependency graph. No live dependency was stopped. |

These are transfer lessons and bounded review findings. They are not a claim that
the public baseline contains the same defects, nor an instruction to modify the
operational prototype as part of this repository change.

### Additional graph and postcondition review

- PL07: a reviewed evidence locator uses a case-folded string's character offset
  directly against the original string. A pure-function synthetic probe with
  `Straße Alpha` and quote `alpha` returned `[8, 13]`, whose original slice is
  `lpha`. Its caller persists the slice at the returned coordinates. This is a
  reproduced coordinate defect; it does not establish which operational claims
  were affected. Preserve original-text coordinates or an explicit normalization
  map. The public implementation must retain its stronger span contract.
- PL08: the reviewed graph worker checks document currentness before computation
  and marks completion by queue identity without an attempt token. This is a
  conditional ownership/late-acceptance concern, not a claim that all prototype
  recovery paths were reviewed or an operational race was observed. Preserve the
  public worker's fencing and revalidate input version, lifecycle and policy in
  the acceptance transaction.
- PL09: the reviewed embedding repair selects and locks documents, computes
  embeddings and then commits vectors in one transaction. This protects input
  consistency but holds locks across expensive computation. Compare it with
  bounded selection, out-of-transaction inference and conditional acceptance of
  unchanged input identity; measure contention before claiming a performance
  defect. The final choice must preserve late-result and retirement protections.

A useful counterexample to purely model-judged output is the reviewed correlation
postcondition: it requires exact equality with a deterministic rendering of
captured source rows. Preserve that integrity pattern, while evaluating whether
the correlation itself is meaningful separately. Several extraction paths also
use explicit document prefixes; record bounded coverage and omitted sections
rather than interpreting process completion as full-document analysis. These
additional reads/probes involved no live model or data mutation.

## Useful behavior to generalize

| Area | Reviewed prototype mechanism | Public implementation decision and proof needed |
| --- | --- | --- |
| Embedding requests | Bounded LRU/TTL query cache, per-key request coalescing, finite-vector validation, bounded in-flight owners and waiter timeout | Retain coalescing as an optional optimization. Keys must include encoder/tokenizer/preprocessing identity, dimension and workspace/disclosure scope. Do not copy a hardcoded vector dimension. Test owner failure, waiter cancellation, capacity refusal and policy invalidation. |
| Inference scheduling | Query priority with a bounded query burst, background document admission and queue measurements | Generalize fairness within shared measured resource admission. A process-local condition does not establish cross-process/GPU ownership. Test sustained query load, background progress, process death and reservation release after confirmed worker termination. |
| Hybrid retrieval | Multiple dense candidate lists, lexical fusion, per-stage timing/errors, section offsets tied to content hash, filtering before result limits and reranking | Keep stage provenance and explicitly degraded results. Multiple encoders remain optional pending independent quality/resource evidence. Compare single-encoder and lexical baselines before adding cost or mandatory dependencies. One absolute request budget must bound all stages. |
| Reranking | Cache identity includes ordered candidate content; ranking output is checked for a complete unique permutation | Preserve content/version binding and reject partial, duplicate or foreign IDs. Bound candidate bytes and cache memory. A valid permutation does not establish relevance or score calibration. |
| Briefings | Deterministic diversity selection combining relevance, lexical similarity, source identity and shared identifiers | Use as a candidate policy, not a semantic-quality oracle. The reviewed selection fills a target/floor; its duplicate-pair counter is informational rather than hard duplicate exclusion. Explicitly choose omission versus quota-filling and test syndicated stories, sparse evidence, ties, nonfinite scores and independent source-family labels. |
| Vulnerability intelligence | Priority-aware score refresh, bounded request counts, retained raw observations, dated scores and separate catalog membership | Build adapters on the existing strict advisory envelope. Preserve revised/retracted/missing records and conflicting authorities. Test actual dates, duplicate/omitted/unrequested IDs, partial responses and stale data. Catalog membership and priority never establish local applicability. |
| Regulatory intelligence | Distinct procedure observations/transitions, publication-family membership, corroboration records, source parser canaries and structured text promotion | Preserve these concepts while correcting PL01/PL02. A canary is bounded source-compatibility evidence, not a proof that all results are complete. Different official interfaces are not automatically independent publishers. Removed members and legitimate repeals need reviewable transitions, not permanent shrink refusal. |
| Evidence publication | Separate snapshot/build/publish/reconcile processes, selected staged bundles, manifest checks and retained receipts | Keep the separation of authority. Correct PL03 and test crash boundaries before/after remote acceptance, stale receipts, duplicate reconcile and unknown outcomes. Do not enable automatic public publishing before disclosure controls pass. |
| Cloud operations | Provider-specific workers, selected release packets, transactional quota reservations, conservative unknown-submission records and catalog discovery separated from promotion | Reimplement on the target PostgreSQL operation/accounting ledger. Process-local semaphores and file reservations alone do not establish distributed admission or power-loss durability. Complete poll/cancel/retrieve/validate/import/reconcile paths; submission and status alone do not close batch support. |
| Context and graph | Explicit context retirement projection; assertion rows bind document content, evidence coordinates, extraction contract, source classification and validation state | Retain relational assertions and reversible projections. Verify retirement across direct reads, caches, graph expansion and future model packets. Do not import personal context or fleet administration authority. A quote match and model confidence do not establish truth or entailment. |
| Operations and assurance | Distinct service identities, resource/time limits, effective sandboxing, role-boundary audit, migration provenance, source/index freshness and pipeline metrics | Consolidate into a small set of parameterized process roles with explicit dependencies and readiness states. Preserve least privilege and bounded metrics; do not reproduce every private unit or duplicate deployment-specific audits. Verify installed service behavior, not just unit syntax. |

## Delivery decisions and alternatives

The no-change option preserves the tested foundation but leaves these profiles
unimplemented. Copying the prototype would accelerate apparent feature coverage
while importing coupling, private data and the defects above. The chosen delivery
approach is to retain the current public core and implement bounded profile slices
against independent synthetic acceptance oracles. These are implementation
priorities, not newly completed capabilities or accepted architecture ADRs.

1. Establish one profile-state/readiness contract and observable attempt, success,
   freshness, coverage and degraded-state semantics. Extend actual installed
   service tests to dependency startup failure and recovery. This makes subsequent
   adapters observable without implying model/domain completeness. Maps to E05,
   E14, E15 and E46.
2. Add immutable domain observation occurrences and accepted-current authority
   before structured regulatory promotion. Test A/B/A, replay after newer state,
   concurrent promotion, stale receipts, partial documents, legitimate removals,
   source canary failure and failure after earlier accepted snapshots. Maps to E02,
   E06, E20 and E33. Record the final schema/compatibility choice in an ADR before
   implementation; published migrations remain unchanged.
3. Implement generic vulnerability acquisition/persistence on the advisory
   contract with external endpoints, source completeness and freshness receipts.
   Test range/applicability separately from acquisition and prioritization. Maps to
   E09, E10, E31, E32 and E40.
4. Add incremental backfill, scoped caches and fair inference scheduling with
   lifecycle invalidation. Benchmark one encoder before an optional ensemble;
   freeze independent held-out retrieval and briefing quality cases before model
   adoption. Maps to E21-E24, E29, E34-E36, E39 and E41.
5. Implement the cloud ledger and fail-closed release policy before native remote
   dispatch or batch submission. Exercise actual adapter code against disposable
   provider fixtures, including unknown outcomes and missing usage. Local/EU
   sovereignty policy remains the default; prototype provider availability grants
   no waiver. Live-provider calls and spending remain separately enabled. Maps to
   E37, E38, E42-E45.
6. Add selected-field export and generation-bound publication/reconciliation only
   after disclosure and authority gates. Finish richer enrichment, context and
   cited products with independent support/omission/diversity evaluation. Maps to
   E17, E18, E25-E30, E44 and E47.

These priorities refine the existing backlog; they do not remove recovery,
all-copy erasure, remote MCP, security/release gates or any optional profile.
Each increment needs a reversible code/config deployment path. Schema changes
need additive migration and matching recovery evidence; a rollback must not erase
accepted observation history. Remote publication and chargeable requests cannot
be made reversible by a local rollback and therefore require reconciliation.

## Verification and remaining uncertainty

Executed for this comparison: selected source/caller reads; 19 installed/source
byte comparisons; read-only catalog inspection of domain/publication structures,
constraints, current-state view and user triggers; effective properties for three
services; one isolated in-memory regulatory replay probe. No data-row inspection
was required. Static counterexamples are labelled above and have not been
presented as operational incidents.

Not established: end-to-end prototype correctness; pretrained semantic quality;
live provider contracts/cost; GPU behavior; performance under representative load;
full unit/dependency coverage; complete role reachability; all parser behavior;
backup/recovery or deletion acceptance. This document does not extend the
revision-bound 630-test implementation receipt. Public source/artifact scans are
publication backstops, not proof that arbitrary material is anonymous.
