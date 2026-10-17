# Reference process deployment

The supplied systemd units are a reference for one Linux acquisition process,
not an installed or accepted deployment. Native unit-parser verification checks
syntax and dependency/executable resolution against an isolated filesystem.
It does not exercise systemd's namespace, cgroup, credentials, timer, networking,
filesystem or termination behaviour. Perform the acceptance checks below on a
separate synthetic deployment before enabling real sources. No actual hosts,
service accounts, source catalogs or credentials are supplied.

## Scope and authority

Install a reviewed wheel and locked dependencies under
`/opt/osint-workbench/venv`; root owns this installation and the service cannot
modify it. Retain the wheel, dependency lock, receipt and migration hashes used.
The CLI requires Python 3.12 or 3.13. This profile uses only core dependencies:
no model, GPU, cloud provider or runtime download is needed. Installing packages
still requires a separately controlled dependency supply chain.

Provision a dedicated non-login `osint-workbench` OS account and group. Its
collector database login inherits only `ow_collector`, without ADMIN OPTION and
with no administrative, reader, writer, lifecycle, GC, recovery or migration
identity attached. Core migration 6 supplies column-scoped collection grants.
Startup validation rejects missing/extra application privileges, delegation,
unsafe memberships, ownership, filtered schemas and mismatched schema/defaults.
The principal can insert accepted evidence and fixed-kind outbox jobs, but cannot
update worker job state or read retained document bodies through SQL. This does
not hide the evidence store from its filesystem owner or provide per-source
tenancy. PUBLIC temporary-object privileges are outside the application-DDL check.
Database permissions and isolation remain essential even with OS confinement.

Root owns `/etc/osint-workbench` with mode 0700. Keep the private canonical
`sources.json` and `collector.env` there with mode 0600. Root's system manager
reads the environment file before switching user. The service account needs
read access to `sources.json`; either make only that file group-readable with
parent directory traversal for the service group, or use a narrowly scoped ACL.
Do not grant write access. Verify access as the actual service account.
The tracked empty `config/sources.example.json` is a safe initial source file;
real URLs stay outside Git.

Set `OW_COLLECTOR_DSN` in `collector.env`; the CLI has no writer fallback. Prefer a libpq service descriptor and
separately protected password file over a password embedded in the DSN; provision
their read permissions for this account and set `PGSERVICEFILE`/`PGPASSFILE`
explicitly when used. Never put any administrative DSN in this file. Environment
variables remain visible to sufficiently privileged processes and potentially
same-user processes. Do not reuse this OS account for untrusted workloads or MCP.
Database certificates and libpq files must be readable within the service sandbox.
A private environment file is not an encrypted secret vault.

The service creates `/var/lib/osint-workbench/evidence` with mode 0700 and sets
`OW_EVIDENCE_ROOT` to it. `ProtectSystem=strict` leaves this managed state directory
writable while code and configuration remain read-only. Private temporary storage
supports bounded parser subprocess work. The account has no capabilities and may
use Unix, IPv4 and IPv6 sockets. Egress is still possible: configure a separate
host/network policy for the intended database, DNS and public HTTP destinations.
The application's HTTP address checks do not constitute an OS egress firewall.

## Bootstrap and enable

1. Provision the database, TLS/authentication policy, account, installation and
   private configuration using the target system's approved mechanism.
2. Stop old collectors and application processes before a schema upgrade. Use a
   separate operator environment with `OW_MIGRATION_DSN` to run
   `osint-workbench migrate`; run `migrate-retrieval` only if that optional profile
   is in use. Remove administrative credentials from the runtime environment.
3. Provision the separate scoped SQL logins and inspect their effective grants.
   Keep lifecycle/policy and recovery credentials under independent custody.
4. Copy `config/systemd/osint-workbench-collect.service` and its `.timer` into
   `/etc/systemd/system` as root-owned, non-writable-by-service files. Do not enable
   the timer yet. Check local systemd support and all paths with
   `systemd-analyze verify /etc/systemd/system/osint-workbench-collect.service /etc/systemd/system/osint-workbench-collect.timer`.
5. Run `systemctl daemon-reload` and start the service once with an empty source
   configuration. Verify the reported unconfigured result and lack of acquisition.
6. Complete disposable synthetic acceptance below. Only then populate the private
   approved source configuration and run
   `systemctl enable --now osint-workbench-collect.timer`.
7. Inspect the first acquisition result and the next timer activation. A successful
   empty-config tick proves neither database access nor acquisition readiness.

The oneshot explicitly uses `--due-only --max-sources 32`. The cap applies to due
mode; manual collection is a distinct operator action. There is no automatic
whole-process restart loop. Durable per-source backoff governs subsequent ticks.
The timer runs about one minute after completion with up to 15 s jitter, beginning
about two minutes after boot. It has no wall-clock catch-up. Database due times
survive process restarts. The timer cannot overlap its own still-running service;
other collectors still require the application's cooperative source locks.

`TimeoutStartSec=15min` bounds the complete oneshot, including HTTP and parsing.
Thirty-two worst-case source attempts can exceed that duration: this is an
intentional supervisor ceiling, not a promise to drain every due source per tick.
On timeout systemd terminates the entire control group, then escalates after
15 s. Previously committed items remain; a later tick reconciles abandoned run
receipts. CPU quota, 768 MiB memory and 32 tasks are initial bounds for this core
collector only. They require target-host measurement and are not inference sizing.
An OOM kill, parser/resource failure or source error can fail a tick and must be
observed; `systemctl` success alone cannot prove all intended sources were served.

## MCP and other workers

There is no MCP service unit. The MCP client starts
`/opt/osint-workbench/venv/bin/osint-workbench mcp` as its stdio subprocess and
owns its lifetime. A background systemd service would sever this transport.
Use a different OS account/sandbox and a dedicated `ow_reader` login, supply only
`OW_READER_DSN`, and mount evidence read-only with narrowly scoped read access.
Do not grant it the collector's group or write access. The collector's 0700
state directory does not automatically grant any reader access: explicitly
provision the separate read-only bind mount/ACL and verify both readability and
write denial. Enforce private source-config/credential denial as well.

MCP clients must preserve stdout for protocol frames and capture diagnostics
privately. The client itself can disclose retrieved content to its own model
provider; read-only local access does not establish data sovereignty outside
that client boundary. Remote authenticated MCP remains a separate unfinished
profile. No model paths, inference processes, chunk worker, enrichment worker,
index build, lifecycle mutation or GC is scheduled by these units. Those roles
need independently reviewed credentials, resource limits and lifecycle supervision.

## Explicit hosted-runner checks

The ordinary suite's `tests/test_deployment.py` performs only native unit parsing.
The separate manually dispatched
[public diagnostic workflow](../.github/workflows/public-encoder-diagnostic.yml)
can additionally run the collector acceptance script on a disposable GitHub-hosted
runner. The actual empty-config service, sandbox and accelerated timeout probes passed
on the named disposable runner; see [the profile receipt](testing/profile-diagnostics.json).
This is separate from native unit parsing and does not establish operational
database-backed deployment acceptance.

The job must create a core installed-wheel virtual environment using the runner's
`/usr/bin/python3`, not a home-directory-managed Python hidden by `ProtectHome`.
The explicit privileged invocation is:

```sh
sudo --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT /tmp/ow-reference-core/bin/python scripts/test_reference_deployment.py --core-venv /tmp/ow-reference-core --units config/systemd --database-fixture
```

Do not invoke this on persistent infrastructure or manually forge the runner
markers. The script also requires systemd as PID 1 and refuses existing fixed
application, configuration, state, account, unit and drop-in targets before making
changes. It relocates the already installed core environment without downloading
packages, provisions a disposable account and empty private source configuration,
and starts the real service. It observes the CLI's unconfigured JSON result and
journal UID. Root-owned probe substitutions retain the reference hardening and
exercise state writes, empty effective capabilities, read-only code mounts and
writable/executable mapping denial. A shortened 2 s start plus 2 s escalation
checks timeout and child termination without waiting for the full 15 min limit.

The script prints only sanitized `PUBLIC_DEPLOYMENT_REPORT` booleans/errors.
It stops the units, checks that they are inactive and removes its owned unit
files in cleanup. Runner destruction removes the synthetic account and remaining
application/state files. These safeguards do not prove the runtime's identity
cryptographically; the workflow must remain restricted to disposable hosted
runners. No source URLs, database credentials, acquisitions, provider requests or
model artifacts are used by this job. A separate encoder diagnostic job in the
same manually dispatched workflow has its own explicit artifact-download scope.

Even a passing result leaves timer activation, live acquisition/database access,
full-duration timeout, memory pressure, target-host resource sizing, production
network policy, other workers and integrated recovery unverified. Record its
exact revision and observed report before describing any property as verified.
See [ADR-0026](adr/0026-bounded-process-supervision.md).

## Synthetic deployment acceptance

Use disposable database and evidence paths; never reuse operational data for
these checks. Establish a synthetic local HTTP fixture route according to the
HTTP transport test boundary. Do not weaken production address policy to admit
an internal fixture.

- Confirm the actual process UID/GID, effective capabilities, read-only code and
  configuration, denied home/device access, and write denial outside evidence
  and private temporary directories. Confirm the account cannot read other roles'
  credential files. Inspect effective unit settings rather than template text.
- Observe one synthetic acquisition, durable source/run state and exact evidence
  hashes, then a second due tick with no dispatch. Advance the controlled fixture
  schedule and verify conditional acquisition and failure backoff.
- Terminate a running tick and confirm all children stop, committed evidence stays
  readable and the next admitted attempt records interruption/replay correctly.
- Exercise the supervisor timeout and memory/task limits. Check the actual failure
  state and bounded diagnostics, then recovery on a later tick. Unit-parser tests
  do not establish these properties.
- Demonstrate the reader's successful stdio MCP request and independent filesystem
  and SQL write denial. Confirm journal access is restricted: IDs, error context
  and acquired metadata can be private even without URL output.
- Take a private checkpoint plus independent current-policy receipt and restore
  into a compatible empty isolated target; validate policy suppression, evidence
  integrity and disabled restored sources before any deliberate re-enablement.

Record the exact wheel, core/profile migration versions, unit hashes, host/systemd
version, relevant effective settings and observed outcomes in a private receipt.
Journal retention, alerts for failed/stale acquisition, disk/inode capacity,
backup custody and tested full-host rebuild remain operator responsibilities;
this reference is not a completed observability or deployment acceptance profile.

## Stop, upgrade and rollback

Stop and disable the timer, then stop the service and verify its control group is
empty before recovery, policy changes or an incompatible upgrade. Preserve failed
run state and private diagnostics for investigation; do not delete CAS objects
or reset due state merely to clear an alert. Install a new reviewed immutable
wheel into a separately staged prefix or environment and switch only while all
affected processes are stopped.

Revert units only to a known compatible reviewed version, reload the manager and
repeat acceptance before enabling collection. Package rollback is safe only when
the older binary explicitly supports the current schema and policy semantics;
there is no automatic down-migration. Otherwise restore a compatible checkpoint
into an empty isolated target using the independent current policy and known
minimum policy revision. Reconcile divergence and explicitly re-enable approved
sources before switching. An old checkpoint alone is not a safe rollback of
retirement or holds. See [recovery](recovery.md), [lifecycle](lifecycle.md) and
[scheduled acquisition](scheduled-acquisition.md) for the implemented boundaries.

Database connection startup uses a fixed 5 s libpq timeout, overriding a longer
DSN value. It applies per host/address attempt; it is not a DNS-wide or whole-tick
deadline. The systemd process timeout remains the aggregate runtime boundary.
The native startup tests use a silent loopback PostgreSQL protocol peer, not a
mock connection. See the revision-bound CI receipt before claiming a tested build.

The manual workflow defaults to `reference-service`; choose `public-encoder` or
`both` explicitly to run the separate pretrained diagnostic. The reference job
adds a fixed disposable PostgreSQL 18 fixture. It refuses existing application
schema/login targets, applies the packaged migrations, and tests a disabled-source
SQL tick under the real service account. It then supplies deliberately broad
synthetic writer/admin identities and requires explicit refusal before source or
evidence writes. Database creation/migration credentials remain in the guarded
fixture setup and deliberate negative probes; they are never a runtime fallback.
Public reports contain booleans, with no raw journal, DSN or credential output.
This does not establish enabled-source HTTP acquisition through systemd, timer
activation, operational credential custody or production deployment acceptance.
