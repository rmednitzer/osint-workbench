# First supervised profile and adoption gates

The bounded profile is RSS/Atom, explicitly configured [static HTML](static-html-acquisition.md),
or single-source API collection,
durable character-chunk processing,
lexical reads and seven stdio MCP tools. Optional local retrieval can be selected
explicitly. It requires separate model-quality and resource acceptance; installing
it does not make it adopted. Enrichment, cloud and domain profiles retain their
own implementation and acceptance work in [the backlog](implementation-backlog.md).
See [ADR-0045](adr/0045-bounded-operational-profile.md).

## Goal and acceptance

On an operator-provisioned supported Ubuntu host, approved external source
configuration shall produce immutable evidence and accepted jobs; bounded worker
ticks shall produce committed chunks; authorized reads shall return verified
content; failed/stale/unconfigured dependencies shall produce a failed aggregate
health result. A private checkpoint plus separately trusted current policy shall
restore into an isolated empty target and preserve accepted content while
respecting later retirement. All real sources and operational deployment details
remain external.

| Gate | Implementation/evidence needed | Adoption condition |
| --- | --- | --- |
| Collection and processing | Installed synthetic transport/parser/DB/store, real timer and worker acceptance | Operator approves actual sources, expected cadence, shared-host limits and egress |
| Read authority | Exact reader grants, actual read-only service storage and seven-tool protocol tests | Intended assistant client tested; its disclosure boundary accepted |
| Health | Explicit thresholds and failed/unavailable-state tests | Operator selects thresholds and monitoring response; no implied SLO |
| Retrieval | Compatible active generation and native inference tests | Independently labelled relevance/abstention and licence/resource gates accepted |
| Recovery | Composed capture/current-policy/empty-target restore and denied rollback tests | Independent custody, backup schedule/expiry, off-host durability, recovery point/time and representative volume measured |

These gates distinguish implemented mechanics from operational acceptance. The
revision-bound results belong in [STATUS](../STATUS.md); this table is not a pass.

## Bounded worker

`osint-workbench work --max-jobs 32` uses only `OW_CHUNK_DSN` and a read-only
`OW_EVIDENCE_ROOT`. The cap is 1–1000 claims per tick, default 32; it is a work
bound, not a throughput target. It claims only `document.accepted`. Successful
jobs commit independently. A failed job increments the aggregate failure count
and yields exit 1 after remaining bounded work; a backend exception stops the
tick with a redacted error. `limit_reached` does not mean more jobs exist, and
`idle_observed` means no job returned by this bounded claim poll, not an empty
queue. A claim can reap its limit of exhausted attempts before reaching an
eligible job; a later tick must poll again. The failed count covers jobs attempted
by this tick, not exhausted jobs reaped during claim admission.

Explicit [chunk operations and receipts](workflows.md#explicit-chunk-recovery-and-receipts)
allow writer-requested recovery without resetting earlier jobs. `work-once`
reports the downstream disposition; bounded `work` retains aggregate tick counts.

`document.chunked` events remain queued for future consumers. Do not delete
them or count them as processed merely to make a queue chart green. Health's
pending threshold counts ready and running jobs of **all** kinds; this growing
downstream backlog is a remaining workflow integration limit.

## Readiness and response

### Sanitized runtime diagnostics

Run `osint-workbench diagnose` for a fixed JSON report of application version,
numeric Python version, architecture, required Ubuntu/Python/x86-64 profile
matching and presence of
the reader DSN, evidence root and encoder/reranker manifest environment variables.
Presence means a nonempty value, not valid configuration. The offline default
does not connect to PostgreSQL, open application configuration/evidence/model
files or execute inference. It reads OS release metadata to identify the runtime.
It prints no environment values, paths, source identities or exception messages.
A runtime match is not an installed-artifact qualification receipt.

Use `osint-workbench diagnose --check-reader` to opt into the existing bounded
database connection and reader-authority validation, followed by a schema-version
read. Only `compatible` exits 0; missing configuration, unsafe/unavailable
authority, invalid status and schema mismatch exit 1 with fixed states. This
check needs only `OW_READER_DSN`; it does not instantiate models or require an
evidence root. `compatible` establishes this sampled reader/schema check only.
It does not test evidence permissions/integrity, active retrieval generation,
deployment-template drift, model identity/quality, freshness, backup or alerts.
Use `status`, explicit `health` thresholds and the separate adoption gates for
those tasks. Offline diagnostics exit 0 even for an unconfigured installation
or a runtime outside the required profiles; inspect the reported fields.

### Aggregate health

Run `osint-workbench health --max-source-age-seconds AGE --max-pending-jobs PENDING
--max-failed-jobs FAILED`, replacing every uppercase token with an explicit
operator-approved integer. Source age accepts 1–31,536,000 seconds; job limits
accept 0–1,000,000. These are configuration bounds, not recommended thresholds.
The command uses `OW_READER_DSN`; configure `OW_EVIDENCE_ROOT` as for other reads.
Add `--require-retrieval` only with an explicitly configured encoder manifest and
an accepted retrieval profile. No model or provider is selected automatically.

Exit 0 means this metadata sample met all supplied limits. Exit 1 means failed
readiness or a sanitized configuration/backend failure. Disabled sources do not
fail freshness, but no enabled sources fails readiness. An enabled source with
no successful observation, stale success, recorded error or future success time
also fails. Source freshness uses database time and its configured freshness
state in addition to the supplied maximum age. Equality with a job limit passes.

The JSON contains fixed reason codes and aggregate counts. It excludes source
names, URLs, model responses, raw exceptions and paths. It does not verify every
evidence object, run a search, execute a model, check a backup, test notification
delivery or prove sustained availability. Status and source aggregates are sampled
in separate transactions; a concurrent update can change the next observation.

| Failed condition | Operator response |
| --- | --- |
| Unavailable/schema/identity failure | Inspect private local service/dependency state; verify matching binary/schema and scoped login; restore access without broadening runtime grants |
| Unconfigured/unobserved/stale/source error | Verify approved configuration, due scheduling, acquisition receipts and transport; retain last good evidence |
| Pending/failed job threshold | Inspect private job status/kinds, worker ticks and lease state; terminal dedup is not an automatic retry command |
| Future source success | Reconcile database clock and recorded state before trusting freshness |
| Retrieval unavailable | Inspect manifest/generation compatibility; use explicitly labelled lexical fallback if its policy allows it |

Install service templates only after the account/storage procedure in
[deployment](deployment.md). A failed health unit is observable locally through
systemd/journald. Operator monitoring and alert routing must be configured and
tested separately; the repository sends no notifications. Keep private journals
and collector details out of public CI/support artifacts.

## Recovery and cutover

Follow [recovery](recovery.md) for private capture and isolated restore. Keep the
current policy revision and its trusted digest outside the rollback set. Do not
put recovery-owner credentials in a recurring worker or infer independent custody
from two files on one host. Stop writes before a planned cutover, verify the
restored database/evidence pair with representative reads, and resume collection
only after explicitly re-enabling approved sources. A source checkpoint restores
with sources disabled. Restore does not requeue uncertain chargeable work.

The repository acceptance adds a composed synthetic collected/chunked recovery
path, including later-policy retirement and invalid-digest/rollback refusals.
This tests logical recovery mechanics across processes. Automation with least
backup authority, scheduling, remote storage, retention/expiry, custody failure,
large-corpus limits and target-host recovery timing still need implementation and
operator acceptance. No RPO/RTO or operational go-live is inferred from the fixture.


## Optional local API enrichment service

The separate [bounded local-API worker](local-inference-api.md#optional-bounded-supervised-worker)
can process explicitly enqueued extraction jobs under a selected manifest. It does
not expand the core chunk worker, approve proposals, qualify a useful model or
close the full enrichment/domain roadmap. Its persistent uncertainty and loaded
credential custody require separate provisioning; the timer is never enabled by
installation. Current revision-bound service evidence belongs in STATUS.


## Runtime capabilities and evidence allocation

See [ADR-0064](adr/0064-security-scan-control-boundaries.md). Provision the chunk
login with only `ow_chunk_worker`. Local enrichment uses only `ow_local_enricher`
and `OW_ENRICHMENT_DSN`; governed generation uses only `ow_dispatcher` and
`OW_DISPATCH_DSN`. Keep `ow_writer` for explicit operator production commands.
Do not combine these memberships or share a login across deployed components.

The database administrator registers the selected enrichment login in
`ow.worker_kinds` with its exact `document.enrich/GENERATOR_SHA256` kind and
`local` or `remote` execution class. Use the generator identity from the selected
validated manifest; changing that manifest requires an explicit assignment update.
The worker cannot register itself. Queue reads remain shared; mutations are
restricted by component, kind, terminal state and authenticated lease ownership.

Select `OW_EVIDENCE_MAX_BYTES` consistently for every writer sharing a CAS root.
The default is a finite 1 GiB library safety bound, not an operational capacity
recommendation. A store also admits at most 100000 objects. Exact deduplication
continues at the limit; new bytes fail with `EVIDENCE_BUDGET_EXHAUSTED`. Inspect
retention and capacity; never delete referenced evidence merely to clear the
alarm. Unknown files or abandoned staging cause `EVIDENCE_BUDGET_UNAVAILABLE`
and require explicit custody/integrity investigation. The private
`.allocation-lock` is part of the writer protocol; do not replace it while writers
are active. External filesystem, database/WAL and backup quotas remain required.

Quiesce workers before migration 13 and provision the new logins before restart.
Historical running jobs can be reclaimed after expiry. Historical remote attempts
with unknown ownership remain for separate accounting, never automatic release.
Recovery does not import `worker_kinds`: reprovision deployment assignments under
administrator authority on the isolated restored target. Binary rollback requires
the matching pre-migration database; an old binary is not a schema downgrade.
