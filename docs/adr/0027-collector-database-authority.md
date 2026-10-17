# ADR-0027: Separate collector database authority from general workflow writes

Status: ACCEPTED for the CLI/reference collector boundary. Date: 2026-10-17.

## Context and decision drivers

The reference collector previously used `ow_writer`, which can enqueue arbitrary
workflow kinds and update job state. Acquisition needs to record source/run/cache
state, insert immutable evidence metadata, reconcile present document heads and
create the fixed `document.accepted` outbox event. It does not need to complete or
cancel jobs, review assertions, activate retrieval generations, change lifecycle
policy, restore data or administer the schema. HTTP source and parser output are
untrusted input; a collector compromise must not automatically receive every
general worker mutation capability.

Preserve parameterized SQL and the existing ingestion transaction rather than
introduce an elevated stored-program boundary. Detect accidental broad grants
before acquisition, preserve empty-configuration non-execution, and avoid silently
reusing a more privileged credential when configuration is incomplete.

## Alternatives, including no change

- Keep the broad writer principal and rely on process convention. This needs no
  migration but leaves unrelated workflow mutation authority attached to the
  network-facing collector.
- Reuse the read-only principal and add a security-definer ingestion function.
  This creates a new elevated interface, owner/search-path trust and function
  validation requirements, and conflates reader and acquisition authority.
- Introduce per-source logins or row policies. This could enforce additional
  isolation but adds source provisioning, policy, migration and recovery scope;
  it is not established by this increment.
- Add a dedicated group with column-scoped acquisition grants and explicit CLI
  identity validation. This is the chosen bounded authority reduction.

## Decision and privilege contract

Add the immutable core-v6 migration and the `ow_collector` group. Provision a
dedicated login for that group; the reference process receives
`OW_COLLECTOR_DSN`, not a general writer or administrative credential. Nonempty
CLI collection requires this variable and validates effective application
privileges before HTTP dispatch. There is no fallback to `OW_WRITER_DSN`.
An empty configuration still returns `unconfigured` without a database connection
and must not be interpreted as database or acquisition readiness.

Grant only the columns needed for source scheduling, run outcomes, snapshot and
document insertion, logical-key suppression checks and document-head acceptance.
No document-body SELECT or job UPDATE authority is needed. The ingestion outbox
INSERT omits `kind`; its database default is `document.accepted`. Grant INSERT
only for `job_id`, `dedup_key` and `payload`, so this principal cannot choose a
different kind or overwrite job acceptance state. Generic writer enqueueing keeps
its separate explicit-kind contract. No security-definer function is introduced.

The startup check must examine effective privileges, dangerous role attributes,
reachable role memberships and ownership rather than merely match a role name.
Unexpected application grants, a missing required grant, broad writer/admin
authority or a mismatched schema must refuse acquisition visibly. The exact
allowlist and tests define this implementation's boundary; role naming alone is
not evidence of least privilege.

Database connection establishment also receives a finite libpq connection
timeout. This bounds the driver's connection attempt under its supported
semantics, not the complete tick or all possible DNS/multi-host behaviour. The
external supervisor remains the whole-process runtime boundary.

## Consequences and residual authority

This separates CLI/reference-process credentials; the trusted Python `collect`
API can still be invoked with an explicitly supplied general writer. It is not
per-source tenancy, row isolation or containment of every SQL action. A collector
can insert evidence and the fixed outbox event for configured source identities
and can update collection state within its grants. Its OS process can read the
CAS files that its filesystem authority exposes; denying SQL body SELECT does
not make that evidence confidential from the collector. The writable CAS is not
an OS-enforced append-only store: a compromised filesystem owner can also remove
objects. SQL DELETE denial does not close that separate availability boundary. Job payload contents
remain subject to downstream validation and existing evidence/fence contracts.

Privilege validation is a startup observation, not continuous attestation of all
future grants, backend identities, schema changes or privileged direct writers.
Operators must quiesce processes for authority/schema changes and prevent the
runtime account from obtaining other credentials or altering its environment.
No new filesystem, network egress, provider, tenant or deployment guarantee is
implied. The existing cooperative source lock and lifecycle barrier remain
necessary and are not replaced by the SQL group.

## Compatibility, blast radius and rollback

Core schema advances to v6; published migrations v1–v5 and retrieval profile v2
remain unchanged. Checkpoint format remains 2 with exact version/hash checks.
Adoption of a supported older checkpoint requires the explicit tested migration
compatibility path and independent lifecycle policy; arbitrary older layouts
must not be accepted by weakening the identity checks.

Scope is the public repository and disposable fixtures, not the original running
prototype. For an operational upgrade, stop the collector, apply the migration
using a separate operator principal, provision/inspect the scoped login and
change only the collector credential reference before synthetic acceptance.
Do not grant broader privileges merely to clear a failed startup check.

Stop collection before rollback. Reverting to a version that requires broad
writer credentials reintroduces the rejected authority and requires an explicit
review; it is not a transparent credential fallback. Preserve the database and
lifecycle policy. An incompatible binary rollback requires the supported isolated
restore procedure, not silent down-migration or modification of published SQL.

## Required verification

Use native PostgreSQL to demonstrate successful full/conditional collection,
head reconciliation and outbox insertion under the new scoped login. Demonstrate
direct denial of job updates, arbitrary-kind insertion, raw body reads, lifecycle
mutation and retrieval activation. Deliberately add table/column grants, broad
role membership and ownership/dangerous role attributes; startup must reject the
identity before network dispatch. Check missing privileges and missing DSN without
credential or raw exception disclosure. Preserve generic writer workflow tests,
core-only installation, retained-state migrations and isolated recovery.

Read the candidate's installed-wheel and profile receipts for actual execution
results. A proposed grant list, mock connection or green empty-config tick does
not establish these postconditions or full deployment acceptance.

## Primary reference semantics

PostgreSQL 18 documents effective column privileges, grant/admin-option tests and
role membership versus immediately usable authority in
[System information functions](https://www.postgresql.org/docs/18/functions-info.html).
The [connection parameter reference](https://www.postgresql.org/docs/18/libpq-connect.html)
defines `connect_timeout` per host/address attempt. These references define driver
and SQL semantics; the revision-bound tests establish the implemented checks.
