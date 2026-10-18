# ADR-0047: Supervise explicit API acquisition ticks

Status: Accepted

## Context and decision criteria

ADR-0046 supplies a bounded acquisition command and credential contract. The feed
service does not discover API configuration. A scheduled API profile needs an
explicit command, systemd credential delivery, observable partial/failure states
and installed service evidence without external requests or private fixtures.

## Alternatives

| Option | Consequences |
| --- | --- |
| Operator-authored cron only | Leaves credential delivery, termination and acceptance unspecified |
| Automatically discover API files in the feed timer | Introduces implicit dispatch and credential selection; rejected |
| Template one unit per arbitrary source | Useful future scale profile, but needs instance/configuration identity and aggregate capacity controls |
| Separate opt-in single-source service and timer | Reuses bounded collection and the existing collector authority with explicit configuration and supervision |

## Decision

Ship `osint-workbench-collect-api.service` and its disabled-by-default timer.
The service reads one private `/etc/osint-workbench/api-source.json` and a separate
root-only `api.env`, uses the existing collector account and evidence root, and
admits one due-aware page per tick. It does not accept instance-selected paths,
automatically discover files, force due time or use `--restart` routinely.

Use the existing collector confinement with a 150 s aggregate start timeout and
15 s stop timeout. The command retains its 60 s network/parser/admission deadline;
filesystem/database finalization can extend it until supervision terminates the
control group. Termination may leave an interrupted run or orphan object; existing
next-attempt and reviewed GC/recovery protocols apply. No tighter capacity or
availability claim follows from these initial limits.

The optional credential drop-in delivers only `provider-token` from a root-private
source file. A systemd reference in the private source configuration must select
that name. No token enters argv or a token environment variable. Plain
`LoadCredential` is not encrypted-at-rest provisioning. The shared-evidence drop-in
must be selected separately for this service if consumers need evidence access.
This reuses the collector UID and does not isolate feed/API credentials from a
compromised collector or introduce per-source rights separation.

A committed nonterminal page returns `partial` with exit zero: the bounded tick
succeeded, while SQL retains `API_PARTIAL` and does not refresh success. Health and
operator monitoring must retain that distinction. Credential, entitlement,
transport and parser failures raise fixed errors and fail the service; disabled,
busy and not-due ticks make no provider request. The completion-relative timer
polls once per minute with up to 15 s jitter; SQL due/backoff remains authoritative.
No replay of missed wall-clock ticks or automatic paid retry is introduced.

## Verification and assurance allocation

Extend the existing explicitly guarded two-LTS disposable service fixture. Its
API peer uses generated TLS material, a random synthetic bearer token, production
DNS/public-address/TLS checks and a disconnected namespace with loopback only.
A fixture-only trust file is selected by the service; TLS validation is not
bypassed. No provider response, credential or certificate key is published.

Observe a partial page, no-dispatch non-due tick, actual accelerated timer-triggered
terminal page, raw evidence, exact heads/outbox, rejected authentication, loaded
credential replacement on reactivation, HTTP 503 backoff, missing credential
refusal before HTTP, recovery without duplicate documents and actual worker and
reader units. Native unit parsing and ordinary protocol tests remain separate
from this privileged evidence. U1/U4/U8/U10/U12 constraints apply; E05/E08/E10/E14
remain broader acceptance scenarios, not closed by this fixture.

## Impact, reversibility and rollback

No schema, dependency, MCP or cloud-policy change. Existing feed units remain
unchanged. No provider adapter, restricted content rights, metered requests,
external source catalogue or operational deployment is selected. Stop/disable
the API timer and stop its service before configuration changes or rollback;
verify its control group is empty. Remove only its selected drop-ins/units and
reload the manager. Accepted data and private continuation remain; preserve a
compatible database/evidence pair. Revoke provider tokens independently if needed.

Actual provider qualification/contracts, public Internet DNS/PKI, full-duration
resource tests, monitored sustained workload and target-host adoption remain open.
