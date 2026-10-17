# ADR-0019: Separate generation, evidence location and factual acceptance

Status: ACCEPTED for local reference implementation. Date: 2026-10-17.

## Context and alternatives

A schema-valid generated statement can cite real text and still misrepresent it.
The alternatives are no derived intelligence, automatic promotion after quotation
matching, or durable typed proposals with independent acceptance and cited products.
No change keeps lexical/retrieval utility but leaves the enrichment scope unmet.
Automatic promotion cannot meet the evidence/semantic boundary. Use proposals and
explicit operator review until independent semantic-quality gates justify automation.

## Decision and criteria

Integrate native local completion over a private Unix socket, with bounded authority,
verified executable/file identities, independent schema validation and durable uncertain
ownership. Reuse fenced durable jobs for acceptance. Record original evidence spans,
polarity, model/prompt identities and append-only reviews. Generate deterministic
reviewed-assertion digests instead of presenting a fallback as deep analysis. This
keeps the useful data-to-product path executable without claiming model correctness.

## Consequences and blast radius

Operator review limits unattended throughput. Quotation location remains distinct
from entailment. Source updates/review withdrawal invalidate active derived products.
Ontology relations are proposals with source mentions, not merged global entities.
Unknown remote-process execution blocks local shared admission until reconciled;
client timeout alone cannot release daemon resource ownership. The scope is the
extracted project and disposable fixtures; original hosts/data are untouched.

## Reversibility and rollback

Disable generator/reranker configuration and workers to use existing core reads.
Reject/withdraw assertions by appending reviews; never delete evidence/history to
hide a failed result. Preserve additive migration v3. Native deployment, model choices,
paid/cloud routes and outbound publication remain independent operator decisions.

## Evidence and limits

See tests/test_generation.py, tests/test_reranker.py, tests/test_intelligence.py and
native pgvector/MCP integration tests. The native fixture is an actual small model
with authored constant weights, not pretrained language-quality evidence. Supply-chain
attestation, semantic evaluation, general graph resolution/diversity, full lifecycle
recovery and other roadmap profiles remain open in STATUS.md.
