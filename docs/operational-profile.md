# First supervised profile and adoption gates

The bounded profile is RSS/Atom collection, durable character-chunk processing,
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

`osint-workbench work --max-jobs 32` uses only `OW_WRITER_DSN` and a read-only
`OW_EVIDENCE_ROOT`. The cap is 1–1000 claims per tick, default 32; it is a work
bound, not a throughput target. It claims only `document.accepted`. Successful
jobs commit independently. A failed job increments the aggregate failure count
and yields exit 1 after remaining bounded work; a backend exception stops the
tick with a redacted error. `limit_reached` does not mean more jobs exist, and
`idle_observed` means no job returned by this bounded claim poll, not an empty
queue. A claim can reap its limit of exhausted attempts before reaching an
eligible job; a later tick must poll again. The failed count covers jobs attempted
by this tick, not exhausted jobs reaped during claim admission.

`document.chunked` events remain queued for future consumers. Do not delete
them or count them as processed merely to make a queue chart green. Health's
pending threshold counts ready and running jobs of **all** kinds; this growing
downstream backlog is a remaining workflow integration limit.

## Readiness and response

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
