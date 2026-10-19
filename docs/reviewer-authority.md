# Reviewer credentials, upgrade and recovery

Core 12 separates review acceptance from the producing writer. Retrieval profile
5 narrows metadata updates. [ADR-0053](adr/0053-reviewer-database-authority.md)
defines the decision and limits. This procedure is for an operator-selected
deployment; repository tests never alter an operational database.

## Provision a reviewer

1. Create a dedicated nonprivileged PostgreSQL LOGIN using the deployment's
   private authentication and secret-delivery procedure.
2. Grant only `ow_reviewer` to that login. Do not grant writer, reader, collector,
   lifecycle, accounting, purger, schema ownership or role-administration authority.
3. Deliver its connection configuration privately as `OW_REVIEWER_DSN` to the
   review command. Do not put connection strings, passwords or login inventories
   in the repository, logs, public CI or shell history.
4. Run `osint-workbench review ASSERTION_SHA256 --decision accept --actor REVIEWER
   --rationale 'Evidence reviewed'` with the dedicated credential.
5. Verify the effective assertion state through the normal reader interface.

Use a direct authenticated connection; the CLI rejects SET ROLE identities. A
pooler must preserve authenticated PostgreSQL session identity rather than
collapse reviewer and writer sessions into a common privileged login. A separate
login establishes a database credential boundary, not a different human reviewer.
The application has no review UI, identity provider or per-workspace authorization.

The command validates its actual connection and refuses broadened effective grants
with `UNSAFE_REVIEWER_IDENTITY`. Fix provisioning deliberately; do not grant more
privileges or substitute the writer DSN to make the error disappear. Direct SQL
writer inserts are denied even if a review INSERT privilege is accidentally added.
Database owners/superusers remain capable of changing the policy and data.

## Upgrade core 11/profile 4

1. Stop producing/reviewing processes and quiesce readers for the maintenance window.
2. Capture a matching private database/evidence backup and independently retained
   current lifecycle-policy receipt using the currently installed version.
3. Record the affected reviewed assertions and cited products in private operator
   records. Historical writer reviews will no longer count as effective decisions.
4. Install the verified candidate artifact using the deployment's normal procedure.
5. Run `osint-workbench migrate` with `OW_MIGRATION_DSN`.
6. Run `osint-workbench migrate-retrieval` with the same migration authority if the
   optional retrieval profile is installed.
7. Provision the separate reviewer credential.
8. Review the retained assertions again through the new credential before relying
   on their cited products. Preserve every original review as historical evidence.
9. Verify reader health, source visibility, product validity and optional index
   activation before resuming consumers and producers.

Legacy reviews keep IDs, actor labels, rationale, decisions and timestamps. They
gain `authority=legacy_writer` and a null `database_principal`. The effective view
returns pending until a fresh authenticated decision. An affected old briefing
returns `BRIEFING_STALE`; re-accepting its unchanged cited assertions can restore
its validity. A rejection keeps it stale. Schema-valid quoted claims still need
semantic review; neither credential separation nor a matching quote proves truth.

## Recovery and rollback

Current format-2 checkpoints retain original database provenance without exposing
it to MCP. A restored principal name is historical data: restore neither creates
that login nor establishes present human identity. Provision current credentials
separately. Exact admitted older checkpoints normalize reviews to legacy authority
and require requalification. Consult [recovery](recovery.md) for supported pairs.

Do not downgrade just the binary or restore writer review grants. To revert an
upgrade, restore a compatible pre-upgrade database/evidence pair and reconcile the
independently retained current lifecycle policy. Reconcile any new review decisions
before reverting; do not silently lose withdrawals made after the backup. Stop and
preserve state if a compatible recovery point or current policy is unavailable.
