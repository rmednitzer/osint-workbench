# ADR-0015: Evaluate quality and drift against frozen independent cases

Status: PROPOSED. Owner: maintainer. Date: 2026-10-17.

## Context
Schema correctness alone cannot measure retrieval usefulness, omissions or unsupported summaries.

## Alternatives and no change
Smoke tests; model self-grading; or frozen held-out labels and hard evidence/authority invariants. No change retains the private prototype and remains preferable to an unsafe or unsupported extraction.

## Decision and tie-breaker
Freeze datasets and targets before model selection; measure retrieval, extraction, citation precision/coverage, abstention, domain contradictions and workload costs. Human/structured oracles primary, model judge supplementary. Favor explicit contracts and failure behaviour with the fewest independently managed authorities.

## Consequences and blast radius
No validated quality claim until targets and held-out results exist. API model identity limits constrain reproducibility. Changes apply only to the extracted project and disposable validation environments.

## Reversibility
Retain previous accepted generation/prompt/model route and compare upgrades before activation.

## Verification
R18,R45,R53; E24,E27,E29,E41. No implementation evidence yet.
