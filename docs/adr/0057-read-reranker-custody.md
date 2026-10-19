# ADR-0057: Own the production read reranker contract

Status: ACCEPTED for the bounded local read profile. Date: 2026-10-19.
Exact revision acceptance belongs to installed/native CI evidence.

## Context and criteria

ReadService retained its caller's mutable reranker and reported the live manifest
identity after scoring. Configuration changes could alter an established service
or label a response with an identity different from the dispatched packet.
LocalReranker also read the live thread setting after serializing that packet.
The correction must bind configured scoring and response identity without changing
reader authority, candidate bounds, raw score semantics or native admission.

## Alternatives and decision

- No change leaves caller ownership and per-call thread drift reachable.
- Compare identities around scoring: misses changed-and-restored values and does
  not validate thread settings, which intentionally are outside semantic identity.
- Freeze every manifest globally: changes direct-client configuration semantics
  beyond the service boundary and is unnecessary for owned configuration.
- **Selected:** the service revalidates a deep manifest snapshot, constructs a
  built-in LocalReranker and captures its identity. Each rank operation separately
  revalidates one snapshot before admission, using it for packet and environment.

Invalid configuration reports RERANK_CONFIGURATION_INVALID. Service validation
follows existing reader-grant and read-only-store validation; it does not claim
zero SQL during construction. Unsupported clients fail closed. Caller subclasses
or instance overrides are not adopted. New configuration requires a new service;
direct clients may still be deliberately configured between calls.

## Impact and recovery

SQL, migrations, dependencies and MCP's seven reads remain unchanged. Empty search
results retain the configured reranker identity without native work. Integrity,
timeout, child lifetime, resource, token and candidate limits remain in force.
Snapshot ownership is not a file lease or a sandbox against privileged mutation of
service internals. Model/tokenizer artifacts are still verified in each child.
Historical responses cannot be requalified by this correction; repeat a needed
read using reviewed unchanged artifacts and a new service, preserving old records.

Rollback is a binary revert with no schema or data conversion. It reintroduces
caller aliasing and per-call thread drift, so keep configuration quiescent if
reverting. No pretrained model adoption, calibration or independent semantic
acceptance follows from synthetic numerical evidence.

## Verification

Baseline regressions distinguish packet/environment drift and invalid configuration
reaching admission. Candidate tests retain real ONNX execution and exact fixture
scores. Actual PostgreSQL search must preserve original identity and scores after
caller mutation; the real MCP transport must return the configured identity and
scores. Existing lifecycle, parent-death and bounded-result cases remain required.
