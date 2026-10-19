# ADR-0056: Bind production index operations to an owned encoder contract

Status: ACCEPTED for the bounded local retrieval profile. Date: 2026-10-19.
Exact candidate runtime acceptance belongs to its installed/native checks.

## Context and criteria

`VectorIndex` captured `space_id` at construction but retained its caller's mutable
encoder. Later nested template changes could make recorded generation metadata,
native chunks or query vectors disagree with that captured identity. An installed
baseline native reproduction retained the old space identity while the changed
document template produced a different vector. It did not exercise SQL persistence;
that boundary needs the actual PostgreSQL/pgvector acceptance cases.

The correction must bind metadata and every operation to one validated contract,
preserve native integrity/admission and SQL lifecycle fences, and retain honest
failure outcomes. It must not silently reconfigure an existing service or relabel
potentially incompatible historical vectors.

## Alternatives and decision

- No change leaves a reachable configuration/identity mismatch.
- Compare caller identity before and after calls: detects many changes, but a
  changed-and-restored configuration can escape the checks; metadata still shares
  caller ownership.
- Freeze all `LocalEncoder` instances globally: affects direct clients and their
  valid packet-bound query-flight behavior beyond the index boundary.
- **Selected:** revalidate and own a deep manifest snapshot and built-in encoder
  per index at construction. Derive space identity from that snapshot. Use this
  client for build metadata, native chunks and queries throughout the index lifetime.

A new index/service is required to apply different configuration. Semantic identity
changes remain subject to generation compatibility and explicit build/activation.
The same index retains its own bounded query-flight sharing; separate indexes do
not inherit the caller's active flights or custom adapter/instance overrides.
Unsupported client types and invalid configuration fail with
`RETRIEVAL_CONFIGURATION_INVALID` before database work.

## Impact, custody and recovery

Scope is the production local index and its `ReadService` integration. Native byte
checks, admission, result bounds, exclusions, publication/status fences, retirement,
purge barriers and reader grants remain in force. No dependency, migration,
profile-version, MCP tool or operational deployment change is introduced. Source
catalogues and private manifests remain external. This is configuration custody,
not a same-UID sandbox or a file lease.

Existing records contain no per-call evidence sufficient to prove that the old
producer never changed configuration. The correction cannot identify or repair
mislabelled historical vectors. Where custody is uncertain, rebuild from reviewed
unchanged artifacts and explicitly activate after the normal corpus/accounting
checks; preserve prior records rather than updating vector identities. Do not
rely on unqualified hybrid results during that requalification.

Rollback is a binary revert; there is no schema downgrade or journal conversion.
It reintroduces caller-configuration aliasing, so keep producer configuration
quiescent and do not treat rollback as historical qualification. Generation rollback
still requires the existing ready, compatible, current-corpus and disposition gates.
Useful models, independent relevance/abstention and broader retrieval acceptance
remain open.

## Verification

Use the actual synthetic ONNX fixture to distinguish the original vector from a
changed document template and reject invalid nested configuration before any SQL.
Native PostgreSQL cases must retain the original generation manifest/dimensions
and exact stored vectors despite caller mutation, and preserve the expected RRF
score after query-template mutation. Existing inference-failure classifications,
failed-build isolation, purge-before-late-dispatch and reader/activation cases must
continue to exercise the real owned client. No model quality is inferred.
