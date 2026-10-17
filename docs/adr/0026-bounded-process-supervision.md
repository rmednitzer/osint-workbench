# ADR-0026: Bound acquisition with an external process supervisor

Status: ACCEPTED for the reference collector units; bounded disposable-runner
execution passed in the [profile receipt](../testing/profile-diagnostics.json). Date: 2026-10-17.

## Context and drivers

The durable due-only collector deliberately performs one sequential tick. Its
per-request deadlines and source-count cap do not provide a whole-tick deadline
or terminate every descendant on an external shutdown. Durable backoff controls
subsequent admission; it is not process supervision. Deployment must preserve
separate SQL and filesystem authorities, immutable installed code and private
source configuration without importing the original prototype's operational files.

The decision criteria are bounded runtime, verifiable termination, explicit
identity, private configuration, reproducible installation, minimal additional
components and an honest distinction between syntax checks and actual runtime
behaviour. Local stdio MCP requires a client-owned process and must retain its
read-only identity.

## Alternatives and decision

No change leaves timeout, restart and privilege management to undocumented
operator conventions. A shell/cron wrapper has fewer configuration files but
requires bespoke child-group handling, resource control and overlapping-run
policy. A container or Kubernetes controller supplies useful additional isolation
and orchestration; introducing its runtime, images, privileges, storage and control
plane now expands the reference deployment and recovery boundary. These remain
possible later profiles, with separate acceptance evidence.

Choose a non-root systemd oneshot plus completion-relative timer as the first
Linux reference. The service runs an installed core wheel with explicit
`collect --due-only --max-sources 32`, with no administrative DSN, model downloads
or embedded source URLs. The timer supplies bounded jitter and does not implement
its own retry loop. Database due times and backoff remain authoritative across
process restarts. The service's 15 min start timeout and 15 s stop escalation
bound one tick; control-group termination includes parser children. They do not
promise to dispatch all 32 sources within every tick.

Code and configuration are read-only, the dedicated evidence directory is
writable, capabilities are empty and privileges cannot be acquired. Resource and
socket-family limits narrow process authority. The writer's SQL scope remains
broader than collection alone, and host-level HTTP/database/DNS egress policy is
not supplied. Runtime secrets stay outside Git. Core collector bounds must not be
reused as inference-worker sizing.

Do not create a background MCP service: its existing stdio transport belongs to
the MCP client process tree. The client must supply a separately scoped reader
identity and read-only evidence mount; it receives neither the collector account
nor the collector's credentials. Other workers, lifecycle operations, GC and
recovery retain separate explicit operator invocation and are not scheduled by
these units.

## Evidence and acceptance boundary

The ordinary suite invokes the native systemd unit verifier in an isolated root.
A negative case proves that unsupported directives produce diagnostics rejected
by the test. This is parser/dependency-resolution evidence, not sandbox execution.

An independently explicit manually dispatched hosted-runner job prepares a core
installed-wheel environment and invokes `scripts/test_reference_deployment.py`.
The script requires root, the GitHub-hosted runner markers, systemd PID 1 and
absent target application/account/unit paths before mutation. It starts the real
empty-source collector and checks its journal identity. Temporary command
substitutions retain the reference service's hardening and check state writes,
zero effective capabilities, EROFS on an otherwise user-writable code-side path,
RWX allocation denial and accelerated whole-group timeout/child termination.
Only sanitized public results leave the process. Owned units are stopped and
removed; disposable runner destruction removes the test account and application
state. Runner markers are admission guards, not cryptographic attestation of the
host. Never set them manually to run this on a persistent machine.

These checks passed in the separately revision-bound profile receipt.
They establish only the tested runner/kernel/systemd boundary.
They do not validate actual feed/database credentials, timer activation, full
15 min timeout duration, memory pressure, target-host sizing, production egress,
operational alerts, policy custody, backup/restore or full-host rebuild. Those
remain deployment acceptance requirements in the runbook.

## Consequences, blast radius and rollback

The reference is simple to inspect and removable without changing a schema. It
requires Linux/systemd and target-host measurement; unsupported confinement must
fail visibly rather than be silently disabled. A timer or unit failure can leave
acquisition stale, while a killed tick can retain already committed documents.
Durable attempt reconciliation and evidence verification remain required.

The implementation changes only repository templates and disposable validation
state. It does not install services on the user's infrastructure. Before an
operational upgrade or rollback, stop and disable the timer, stop the service and
verify that its control group is empty. Restore only compatible reviewed units
and installed wheels. A binary rollback is not permission to reverse database
migrations or lifecycle policy. An incompatible rollback requires a tested
isolated restore with independent current policy and deliberate source
re-enablement. See [deployment](../deployment.md) and [recovery](../recovery.md).
