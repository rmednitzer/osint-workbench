# Operations, recovery and lifecycle specification

Use one operational ownership model for configuration, migrations, code/model artifacts, data and generated products. Each installed profile declares dependencies, startup/health/ready semantics, authorities, limits, secret sources, storage and recovery. Enabled but failing is degraded/unavailable; intentionally disabled is disabled; empty source/provider config is unconfigured. Liveness alone is insufficient.

## Database and storage

Use direct PostgreSQL repositories with explicit transaction ownership, foreign keys/unique constraints, query limits/timeouts and workload indexes supported by EXPLAIN/observed tests. Review extension ownership and migrations; do not run arbitrary privileged extension code from MCP. Separate DDL/collector/enrichment/vector/provider/accounting/reader roles and test actual grants/functions. RLS is an optional additional control, never a substitute for authenticating caller/workspace. Avoid SECURITY DEFINER by default; if necessary, pin owner/search_path/execute grants and review reachable writes.

Back up database, evidence and relevant job/model/index manifests as a consistent generation. Define accepted-write checkpoint and quiesce/snapshot protocol; hashing a file set alone does not establish transactional consistency. Derived indexes can be rebuilt only when source snapshots, chunking/model versions and code are preserved. Back up configured workspaces, routing policy and encrypted credentials separately; do not publish their values. WAL/PITR is an explicit profile requiring restore testing. Restore on a fresh isolated installation, verify all references/hashes and query through MCP before readiness.

Model/index upgrades use new generations, quality evaluation and bounded canary activation. Database migrations prefer expand/migrate/contract; destructive transformations require verified backup recovery. Document which data formats allow previous-code rollback. Do not promise rollback after an incompatible migration without restoring the matching pair. No operations are applied to the original prototype by this plan.

## Observability and diagnostics

Measure collection success/failure/age; extraction coverage; chunk/vector/index generation/coverage; job attempt/queue/lease age; model load/admission/latency/OOM; cache hit/failure; provider refusal/usage/unknown outcomes; report citation/quality state; domain source freshness; backup/restore verification. Metrics labels are bounded aggregate categories, not raw URLs, prompts, user queries, personal source labels or arbitrary model-response strings. Request IDs and restricted logs support diagnosis without leaking them into public outputs.

Provide generic metrics exposition, an example dashboard and alert rules for enabled-profile failures, stale sources, hung leases, index mismatch, failed recovery and unknown accounting. Do not claim an SLO from a single benchmark. Proposed capacity/SLO limits must be frozen from a stated workload and operational purpose. Diagnostics redact paths/DSNs/credentials and do not print environment or raw content. Support bundles are explicit local artifacts, scanned before sharing.

## Retention, deletion and holds

Classify raw evidence, normalized text, chunks, vectors, assertions, contexts, prompts/results, accounting, reports and backups separately. Set operator-configured retention and legal/research holds. GC uses reachability plus holds, dry-run output and target checks; no blind timestamp deletion. Deletion/tombstones propagate through graph, search generations, caches, queued jobs and future prompts, and prevent reingestion if the applicable policy requires it. An immutable report may be marked superseded/withdrawn rather than silently rewritten.

Backups and remote provider/published copies have separate retention and deletion limitations; never claim deletion everywhere after removing a live row. Secure secret storage and encrypted backups must use operator-managed keys with a recovery procedure, not embedded credentials. Restore must reapply deletion/hold policy before serving restored content. Keep only minimal private audit evidence necessary for operation.

## Configuration and supply chain

Version configuration schemas with migration validation and explicit secret references. Default secrets/env/source/model download paths are empty. Pin and verify code/container/package/model artifacts, preserve required notices and review custom executable model code. Dependency update proposals run regression and quality gates before activation; model catalogue refresh never updates active routes automatically. All checks are runnable outside GitHub and distribution can be mirrored without proprietary runtime control planes.

End-to-end tests include loss of database/object/model/provider dependencies, restart/partition, overlapping schedules, stale caches, cancellation, disk-full/permission errors in disposable volumes, restored stale jobs and accounting unknowns. Cleanup deletes only resources created by the harness. No live fault injection, fleet modifications or unsolicited notifications are authorized by this design.
