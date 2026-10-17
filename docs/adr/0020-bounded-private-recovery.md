# ADR-0020: Restore a bounded private checkpoint before expanding lifecycle effects

Status: ACCEPTED for the reference profile. Date: 2026-10-17.

## Problem and decision

Independent database and directory copies can expose metadata whose evidence was
never captured. Restoring live leases can also repeat external effects. Implement
a private, bounded logical checkpoint using one MVCC snapshot and verified
referenced immutable objects. Restore into an empty migrated database and an absent
object root. Fixed allowlisted tables and bound JSON values replace executable
database dumps. Require an independently retained digest and matching migration,
PostgreSQL-major and optional pgvector-version identities.

Source collection is disabled on restore. Unfinished jobs lose their fences and
receive failed reconciliation receipts. Incomplete builds/runs are failed or
interrupted. Reader-visible completed evidence, review ordering and compatible
active retrieval generations remain intact. No MCP recovery/write tool is added.

## Alternatives and consequences

A quiesced physical backup plus WAL/PITR scales better and can recover host-level
state, but requires a separate deployment/storage contract not yet implemented.
Database-only exports and hash-only directory listings cannot demonstrate joined
recovery. Arbitrary SQL dump import introduces avoidable executable authority.

The reference format caps rows, metadata and object bytes and holds the bundle in
memory. It contains private data and is neither encrypted nor signed; operators
provide encrypted storage and independent digest custody. Secrets/configuration,
models, roles and inference ownership remain separate. No zero-data-loss, full-host
recovery, retention, public-export or global-erasure claim follows from this choice.
Concurrent future GC must coordinate with checkpoints rather than delete evidence
being captured. See [the operational contract](../recovery.md).

## Recovery and evidence

Database insertion is transactional; failed restores can leave unreferenced private
objects, never a partially accepted dataset. Populated targets cannot be retried
blindly. Regression evidence uses fresh PostgreSQL databases and actual reader/MCP
and hybrid queries, including corrupt-bundle rejection and post-restore review
withdrawal. These address R14 and a bounded subset of E13. Consumer export under
R22/E17, publishing under R51/E47 and retention/deletion under R29/R54/E48 remain
open; private recovery is not evidence of those effects. Published migrations
remain unchanged. The revision-bound CI receipt determines verified scope.
