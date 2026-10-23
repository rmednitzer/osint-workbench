# ADR-0065: Describe paired ranking changes without adopting a model

Status: ACCEPTED for bounded offline comparison. Date: 2026-10-23.

## Context and decision criteria

ADR-0025 supplies strict, suite-bound ranking replay; ADR-0055 adds stand-alone
reranker execution. Aggregate equality can conceal improvements on some queries
and regressions on others. Comparing separately copied totals also risks mixing
suites or losing prediction identity. The public diagnostic remains exposed,
AI-assisted development evidence. Independent labels, answerability calibration,
representative deployment and model adoption remain open under ADR-0015.

Choose a reproducible descriptive comparison that reuses the scorer, preserves
exact input identities, exposes paired changes and missing populations, and adds
no execution or adoption authority. A numerical gain is not population evidence.

## Alternatives, including no change

| Option | Consequence | Decision |
| --- | --- | --- |
| No change; inspect separate replay receipts manually | Preserves current behavior but makes pairing and source-identity mistakes easier | Retain as a valid fallback |
| Ad hoc spreadsheets or copied aggregate totals | Flexible, but pairing/denominators and provenance depend on separate manual work | Not the repository contract |
| Automatic significance tests, confidence intervals or winner selection | Requires independent-unit, sampling and decision assumptions absent from supplied fixed suites | Rejected for this increment |
| Serialize copied Python model inputs before validating | Can omit undeclared fields and allocate oversized serialized output before bounds apply | Rejected; accept bounded bytes only |
| Versioned paired replay with fixed descriptive limits | Reuses strict scorer semantics and retains query-level changes without making adoption claims | Selected |

## Decision and externally visible contract

Add `evaluation.compare(suite_data, baseline_data, candidate_data)` and
`evaluate compare`. The Python API accepts original serialized JSON bytes only.
Use the existing strict parsers, enforcing the 8 MiB per-input bound before JSON
parsing and rejecting unknown wire fields. Refuse Python model objects without
traversal or serialization: schema serialization can silently omit undeclared
copied-model state and allocate unbounded output before validation. This avoids
serializer errors/warnings and a second structural-validation implementation.
Require both complete prediction sets to bind the same canonical validated suite. Pair by query ID,
never file ordering; reuse the existing scorer without changing its version.

The format-1 `paired_ranking_comparison` receipt and policy
`paired-ranking-replay-v1` bind the suite, scorer, both prediction/manifest
identities and replay receipt identities. Record split summaries, aggregate
candidate-minus-baseline deltas, per-query deltas and improved/regressed/unchanged
counts. Use exact deterministic metric equality for ties. Preserve separate
answerable/unsupported populations; absent populations produce null deltas and
zero paired counts. Retain each system's numerical gates.

The CLI writes an absent private file using the existing durable no-overwrite
writer. Exit 0 means a valid comparison was written, even for regression or unmet
targets; exit 1 means input or persistence failure. No numerical adoption decision
or exit-2 target gate is introduced for comparison. Explicit semantic-acceptance
and uncertainty limitations stay in every receipt. This leaves replay/local
execution exit semantics and their historical receipts unchanged.

## Threat and STPA assessment

The boundaries are operator-selected JSON, strict parsing/scoring and private
receipt publication. Inputs and declared model/label provenance remain untrusted
evidence. The tool gains no MCP, SQL, model, network or service authority.

Existing H1/H5/H8, C9/C12/C38/C41 and U38/U41 apply: private diagnostics must not
leak; unrelated or incomplete evidence must not become acceptance; hashes and
ranking gains must not imply independent quality. Refine those allocations in
[STPA](../assurance/stpa.md#paired-ranking-comparison-adr-0065): enforce exact suite
identity and coverage on both sides, visible missing populations, paired query
identity, safe errors and no overwrite. No new controller, hazard category or
runtime trust boundary is required. No broader threat-model completeness is
claimed. Independent label custody and truthful execution provenance require
separate evidence; this tool cannot attest either.

## Consequences, blast radius and rollback

Only the operator CLI and offline Python evaluator gain a capability. Comparisons
consume the existing bounded suite/prediction budgets; input texts and model paths
are absent from the comparison payload. Operator-provided IDs may still be
sensitive, so keep private receipts private and review before publication.
No schema, service, index, route, deployed model or dependency changes occur.

Retain raw predictions, suite, execution protocol and prior receipts. Revert this
command/API to the preceding version and continue separate replay; retain its
comparison receipts with this decision/policy identity rather than rewriting
historical files. A future change to scoring or comparison semantics requires an
explicit compatible/versioned contract. No data migration or model rollback is
needed because comparison cannot activate anything.

## Verification and remaining gates

Regression cases discriminate independent arithmetic, query reordering,
improvement/regression/ties, missing populations, wrong-suite inputs on either
side, model-object refusal without serialization, byte bounds, undeclared nested wire
fields, offline CLI and no-overwrite
private persistence. Required installed/native CI is revision-bound evidence,
separate from this decision. Existing public predictions can exercise replay
without new inference; their equal metrics and failed abstention remain negative
observations. Controlled labels, a frozen acceptance protocol and appropriately
designed uncertainty/resource analysis remain prerequisites for qualification.
