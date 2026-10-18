# Reference process deployment

The supplied systemd units cover Linux acquisition and an optional supervised
chunk-worker/aggregate-health profile. They require separate revision-bound
synthetic acceptance and operator provisioning before operational deployment.
Native unit-parser verification checks
syntax and dependency/executable resolution against an isolated filesystem.
It does not exercise systemd's namespace, cgroup, credentials, timer, networking,
filesystem or termination behaviour. Perform the acceptance checks below on a
separate synthetic deployment before enabling real sources. No actual hosts,
service accounts, source catalogs or credentials are supplied.

The [operational profile](operational-profile.md) defines its goal, health
semantics and remaining adoption gates. The procedure below first describes
private collector storage; the shared profile is a separate explicit choice.

## Optional shared worker and health profile

Provision separate non-login accounts `osint-workbench-worker` and
`osint-workbench-health`, each with its own primary group. Provision the
`osint-workbench-evidence` read group and grant both accounts supplementary
membership. The collector owns evidence; neither consumer joins its private
account group or receives its acquisition credentials. These names are generic
template identities, not an inventory of an operational host.

Start from an empty, collector-owned evidence root with the evidence group's
numeric GID and mode 2750. Provision parent traversal explicitly without making
private directories public. Stop all users of an existing private store before
planning a separately reviewed custody migration; the code does not convert
private objects or recursively change their permissions.

Install `osint-workbench-collect-shared.conf` as a root-owned collector service
drop-in under `osint-workbench-collect.service.d/`. It selects the evidence group
and shared state-directory mode. Set `OW_EVIDENCE_READ_GID` to its actual numeric
GID in the private `collector.env`. The creating process must use that group as
its effective primary group; supplementary membership alone is insufficient.
The explicit creation profile verifies
no-symlink anchored directories, ownership, group, modes and root identity.
POSIX access/default ACLs are refused to avoid hidden named-principal access.
New subdirectories use 0750 and objects 0640 even under umask 0077. No application
chmod requests a setgid bit; `RestrictSUIDSGID=yes` remains enabled. Existing
incompatible objects/directories cause refusal, never implicit disclosure or repair.
Staging remains private until complete bytes are flushed and shared publication
is prepared. Cooperative concurrent creation of the same new prefix can fail
closed during its permission transition; retry only through the normal bounded
collection workflow. Group members can read every object in this selected store;
this is not document authorization. Keep unrelated workloads out of the evidence
group.

Install the worker's environment as root-owned mode 0600
`/etc/osint-workbench-worker/runtime.env`, containing only its `OW_WRITER_DSN`
and any explicitly needed libpq configuration. Install the health environment
similarly at `/etc/osint-workbench-health/runtime.env`, with `OW_READER_DSN` and
explicit `OW_HEALTH_MAX_SOURCE_AGE_SECONDS`, `OW_HEALTH_MAX_PENDING_JOBS` and
`OW_HEALTH_MAX_FAILED_JOBS`. Root's service manager reads environment files;
client certificates/password files need narrowly provisioned account-readable
paths in that role's configuration directory. Environment values are process
secrets, not encrypted storage. Do not put migration, recovery, lifecycle,
accounting or provider credentials into either environment.

Copy the `osint-workbench-work` and `osint-workbench-health` service/timer pairs
as root-owned system units and verify their syntax before enabling them. Each
consumer mounts evidence read-only, cannot access the other roles' configuration
directories and runs without capabilities. PostgreSQL connections may use Unix
or IP sockets; configure host egress policy separately. The core health template
does not load an encoder. An operator-selected retrieval health profile requires
a reviewed ExecStart override adding `--require-retrieval`, its encoder manifest
and measured resource/sandbox adjustments; the metadata gate does not run a model.

Run collection, worker and health services manually first and inspect their
private results. Prove a newly collected object is readable by both consumers,
cannot be written by them, and their SQL identities cannot acquire broader roles.
Only then enable the worker/health timers. The worker ticks 30 seconds after
completion with up to five seconds jitter; health ticks one minute after completion
with up to ten seconds jitter. Both start about three minutes after boot and
cannot overlap their own unit. Their timeout/resource limits are initial hard
bounds, not accepted capacity. No missed wall-clock runs are replayed.

A failed health observation yields a failed service with aggregate journal output.
Configure and test the operator's monitor/response separately. The repository
sends no alerts and gives no default SLO or recovery target. Worker/health units
remain disabled by default. Restored evidence is private; do not enable shared
consumers against it until explicit custody provisioning is complete.

## Scope and authority

Install a reviewed wheel and locked dependencies under
`/opt/osint-workbench/venv`; root owns this installation and the service cannot
modify it. Retain the wheel, dependency lock, receipt and migration hashes used.
The CLI supports CPython 3.12–3.14. Use the system Python in a dedicated venv
on Ubuntu 24.04 (3.12) or 26.04 (3.14), with the
[runtime verification limits](runtime-support.md). This profile uses only core dependencies:
no model, GPU, cloud provider or runtime download is needed. Installing packages
still requires a separately controlled dependency supply chain.

Provision a dedicated non-login `osint-workbench` OS account and group. Its
collector database login inherits only `ow_collector`, without ADMIN OPTION and
with no administrative, reader, writer, lifecycle, purge, GC, recovery or migration
identity attached. Core migrations 6 and 8 supply column-scoped collection grants.
Startup validation rejects missing/extra application privileges, delegation,
unsafe memberships, ownership, filtered schemas and mismatched schema/defaults.
The principal can insert accepted evidence and fixed-kind outbox jobs, but cannot
update worker job state or read retained document bodies through SQL. This does
not hide the evidence store from its filesystem owner or provide per-source
tenancy. PUBLIC temporary-object privileges are outside the application-DDL check.
Database permissions and isolation remain essential even with OS confinement.

Root owns `/etc/osint-workbench`. One concrete layout uses the service group
on that directory with mode 0750, root-only `collector.env` with mode 0600, and
root-owned `sources.json` with the service group and mode 0640. Root's system
manager reads the environment file before switching user; the service account
can traverse the directory and read only its source file. A narrowly scoped ACL
can provide equivalent access. Do not grant the account configuration write
access or environment-file readability. Verify access as the actual service account.
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
Do not grant it the collector's private account group, credentials or write access.
The private 0700 store does not grant reader access. Explicitly provision the
shared creation profile above and select its read group for this account, then
verify both readability of newly created objects and mount-level write denial.
Directory ACL inheritance alone cannot override private 0600 object creation;
do not assume it provides continuing read access. Enforce private source-config/
credential denial as well. The selected group reads all retained CAS bytes;
SQL lifecycle filtering does not erase or authorize each filesystem object.

MCP clients must preserve stdout for protocol frames and capture diagnostics
privately. The client itself can disclose retrieved content to its own model
provider; read-only local access does not establish data sovereignty outside
that client boundary. Remote authenticated MCP remains a separate unfinished
profile. The optional worker pair schedules character chunking only. No model
paths, inference processes, enrichment worker, index build, lifecycle mutation
or GC is scheduled by these units. Those roles need independently reviewed
credentials, resource limits and lifecycle supervision.

## Explicit hosted-runner checks

The ordinary suite's `tests/test_deployment.py` performs only native unit parsing.
The separate manually dispatched
[public diagnostic workflow](../.github/workflows/public-encoder-diagnostic.yml)
can additionally run the service acceptance script on a disposable GitHub-hosted
runner. Earlier receipts record successful empty-config service, sandbox and
accelerated timeout probes, followed by scoped PostgreSQL/disabled-source checks;
see [the profile receipt](testing/profile-diagnostics.json) and
[the collector receipt](testing/collector-deployment.json). The earliest empty/disabled-source attempts did not
exercise enabled HTTP acquisition or timer activation; the later enabled-source
receipt below did. Native unit parsing is a separate, narrower evidence level.

The enabled-source extension passed at core schema 7 on source
`064be8bb629a61e50ed9d4708a52a7b13675cb28`, as recorded in the collector receipt.
That historical receipt preserves failed fixture attempts and their corrections.
It does not establish service acceptance for the current core schema 11,
MCP/dependency closure, both LTS runners or this documentation revision. Repeat
the manual workflow for the intended candidate and retain its observed reports.
A successor [2026-10-18 service receipt](testing/documentation-service-2026-10-18.json)
records core-10 acceptance on both LTS defaults at `ebdbf666e0f4001dca59ce8760386aae80408d61`,
including current-head reuse after one changed feed item. Its installed wheel
is identified separately for each runner. This synthetic HTTP/timer result remains
separate from operational deployment acceptance.

The [operational-profile service successor](testing/operational-service-2026-10-18.json)
records source `d4a1e64be1e399eb052db13f35ddcf0fc5234b81` on both LTS defaults,
including separate worker/health accounts, authentication failure recovery,
read-only shared evidence access, lexical reads, explicit health failure/recovery
and accelerated worker/health timer activation. It identifies the exact installed
wheel and owned-unit cleanup. Production timer durations, sustained load, model
quality and operational deployment remain outside this fixture.

The job must create a core installed-wheel virtual environment using the runner's
`/usr/bin/python3`, not a home-directory-managed Python hidden by `ProtectHome`.
The explicit privileged invocation is:

```sh
sudo --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT /tmp/ow-reference-core/bin/python scripts/test_reference_deployment.py --core-venv /tmp/ow-reference-core --units config/systemd --database-fixture --enabled-http-fixture --operational-fixture
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

The manual workflow defaults to `reference-service`; that selection runs the
service matrix on Ubuntu 24.04 and 26.04 without the pretrained encoder job.
Choose `public-encoder` or `both` explicitly to permit the separate pretrained
diagnostic and its model download. Select the reviewed branch or tag when
dispatching and verify the run's resolved source commit; ordinary foundation CI
does not run this privileged acceptance. The reference job
uses a fixed disposable PostgreSQL 18 container. It refuses existing application
schema/login targets, applies the packaged migrations, and tests a disabled-source
SQL tick under the real service account. Deliberately broad synthetic writer/admin
identities must be refused before source or evidence writes. Administrative
credentials remain in guarded setup and negative probes, never as a runtime
fallback.

## Isolated enabled-source fixture

The optional `--operational-fixture` requires both fixture flags below and all
disposable-runner guards. It provisions the explicit shared creation profile and
separate worker/health accounts. It proves failed worker authentication leaves
durable jobs untouched, successful chunking, idle restart without duplicate rows,
new-object readability and write/configuration denial under the actual consumer
units, lexical reader execution, failed and recovered health thresholds, and
accelerated activation of both new timers. These are synthetic functional probes,
not sustained capacity, representative recovery or operational deployment.

The optional `--enabled-http-fixture` requires `--database-fixture`. It creates
the fixed owned `ow-reference` network namespace containing only loopback and a
synthetic public-classified `93.184.216.34/32` address. It verifies the namespace
identity, interface/address set and route inventory before binding HTTP port 80.
No veth, external network interface or external route is created. The address is
fixture data, not an Internet endpoint under the project's control.

A root-owned service override supplies `NetworkNamespacePath` and a read-only
hosts-file bind mapping `feed.fixture.invalid` to that address. The unchanged
installed collector resolves and fetches `http://feed.fixture.invalid/feed`
through its production URL, DNS, public-address, deadline and HTTP checks. No
resolver monkeypatch, private-address exception or application fixture flag is
used. The scoped collector connects to the disposable PostgreSQL container through
a Unix socket visible inside the namespace. Explicit local/host SCRAM setup and
a wrong-password authentication failure at that same endpoint must exclude a
permissive local-trust connection before the fixture can claim authenticated
database integration.

The required sequence is initial HTTP 200 acceptance, an actual timer-triggered
304, controlled HTTP 503 with durable backoff, a non-due tick with no HTTP request,
then unconditional acceptance of a changed representation after failure.
The changed feed preserves item One and revises item Two: two processed items
are reported, but only one new document/job is created, for three retained
versions/jobs in total. The unchanged current-head identity must remain stable.
The 503 fixture requests a 120 s Retry-After delay; acceptance must observe that
durable delay beyond the 60 s local failure floor before testing no dispatch. The
fixture adds an explicit 1 s activation arm and accelerates recurring inactivity
scheduling to 1 s, with zero jitter and 100 ms accuracy. It advances only the
synthetic source's database due time. Earlier probe failure state is reset before
arming; production timer configuration and start-rate limits remain unchanged. It cross-checks request/validator
observations, PostgreSQL run state, exact raw/text CAS bytes, current heads,
fixed-kind outbox events and the journal's service UID. Neither a process exit
nor a timer's presence alone establishes these outcomes.

The script prints a sanitized `PUBLIC_DEPLOYMENT_REPORT`. Failure diagnostics
contain only allowlisted command/state/exception categories, bounded counts and
known harness basenames/line numbers; raw arguments, exception messages and
journals remain excluded. Timer progress uses the raw D-Bus unsigned integer
property while the unit is active, rather than parsing formatted CLI durations.
It stops the owned units and HTTP process, checks their state and namespace use,
and removes its owned overrides, namespace and unit files in cleanup. Preexisting
fixed resources cause refusal; a cleanup failure remains a failed result. Runner
destruction removes the synthetic account, database and remaining
application/state files. These safeguards do not prove the runtime's identity
cryptographically; the workflow must remain restricted to disposable hosted
runners. Linux namespace/systemd support and administrative capabilities are
prerequisites; their absence must not be worked around by weakening production
network policy. The job uses only fixed public synthetic source/configuration and
disposable test credentials. It uses no operational sources, provider requests or
model artifacts. The separate encoder diagnostic has its own explicit
artifact-download scope.

Even a passing enabled-fixture result leaves Internet DNS, TLS/certificates,
external publishers, production timer cadence, full-duration timeout, memory
pressure, target-host resource sizing, operational credential custody, production
egress policy, other workers and integrated recovery unverified. It demonstrates
only the observed synthetic HTTP/database/service path on the named runner.
Record the exact revision, wheel identity and observed report before describing
any property as verified. See [ADR-0026](adr/0026-bounded-process-supervision.md)
and [ADR-0028](adr/0028-isolated-enabled-source-service-fixture.md).

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

The scoped SQL role does not make the writable evidence directory append-only at
the OS boundary. A compromised filesystem owner can read or unlink CAS objects;
separate storage authority and recovery controls remain necessary. This reference
does not claim containment of a malicious collector process.

The historical [collector deployment receipt](testing/collector-deployment.json)
records successful enabled-source HTTP acquisition, accelerated timer activation,
SCRAM and sandbox checks on its exact source revision and measured installed
wheel. It preserves all failed fixture attempts and the earlier source-bound
disabled-source receipt, whose manual wheel digest was not recorded. Earlier
native retirement-test corrections remain in the verification receipt. These
results establish only the bounded synthetic path at that recorded revision;
newer schema/dependency changes require fresh manual service acceptance. The
[core-10 successor receipt](testing/documentation-service-2026-10-18.json) supplies
that bounded two-LTS evidence for its own named source and wheel, without
relabeling earlier receipts or proving every subsequent revision.
