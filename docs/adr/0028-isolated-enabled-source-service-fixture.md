# ADR-0028: Exercise enabled acquisition through an isolated real service fixture

Status: ACCEPTED for explicit disposable-runner acceptance. Date: 2026-10-17.

## Context and decision drivers

The reference service probes establish selected process properties and a disabled
source's scoped PostgreSQL writes. They do not establish that an enabled source
can traverse the real service's DNS/address policy, HTTP transport, parser,
database, evidence store and conditional/retry schedule together. Existing native
HTTP tests deliberately route a fixture around production destination policy;
they cannot independently establish that deployed policy integration.

Production acquisition intentionally rejects private and loopback destinations.
A new fixture must preserve that restriction and avoid a live public feed or a
route to a real external address. It must prove request and acceptance behaviour
through the actual service account, installed wheel and supervisor, while keeping
all acquired data synthetic and the destination isolated.

## Alternatives, including no change

- Keep only empty/disabled-source probes and routed native HTTP tests. This
  preserves their existing evidence but leaves enabled deployed integration open.
- Add a production private-address override, resolver hook or fixture transport
  flag. This weakens or forks the production path and creates a new capability
  that could be misconfigured operationally; reject this alternative.
- Use a real public feed. This depends on an external publisher and network,
  exposes source-selection metadata and cannot provide deterministic failure and
  conditional-response controls; reject it as acceptance evidence here.
- Bind a fixed public-classified address only inside an isolated network
  namespace, with no external route, and run the unchanged acquisition path.
  Choose this fixture within explicitly guarded disposable Linux runners.

## Decision and isolation boundary

The manual acceptance harness creates a fixed, owned network namespace on a
disposable GitHub-hosted runner after its existing root, runner, PID1 and
owned-path preflight guards. The namespace contains only loopback. A fixed
`93.184.216.34/32` fixture address belongs to that loopback interface; no veth,
external interface or route to another network is introduced. Interface,
namespace identity, address and route checks are prerequisites to binding or
dispatching to the public-classified address. The address is fixture data, not a
claim of control over that address on the Internet.

The actual systemd collector joins the namespace and receives a read-only hosts
file mapping the fixed `feed.fixture.invalid` name to the fixture address. Its
production URL, DNS resolution, public-address checks, deadline and HTTP stream
remain unchanged; no monkeypatch or application network bypass is accepted.
The HTTP server's controlled phases return a complete representation, matching
304, visible 503 failure and a subsequent changed complete representation.

The namespace reaches the disposable PostgreSQL fixture through a Unix socket,
not a route back to the host network. Explicit SCRAM local/host authentication
and a bad-password rejection at the same endpoint distinguish actual password
enforcement from a container's permissive local authentication. The service
receives only the scoped collector login. PostgreSQL administration remains in
the guarded harness, outside the service's credentials and authority.

An accelerated timer override tests real timer-triggered conditional acquisition.
It is a fixture override, not evidence that production intervals or host sizing
are correct. Operator-controlled phase changes and database due-time advancement
allow bounded failure/backoff/no-dispatch and full changed-body recovery checks.
Raw CAS hashes, current document heads, fixed outbox events, HTTP/run state,
observed requests and journal service UID must agree; process exit alone does
not establish acceptance.

## Failure, ownership and cleanup

Refuse missing namespace/capability support, a preexisting fixed namespace or
fixture path, unexpected network state, unsuitable authentication or an unsafe
database principal. Do not broaden privileges, add an egress route or bypass
production address checks to make the fixture pass. Runner environment markers
are guard inputs, not cryptographic proof of host identity. Never set them on a
persistent machine to obtain permission to run this harness.

Track resource ownership immediately after creation. Failure cleanup stops the
owned timer/service and verifies their state, stops the owned HTTP process and
removes only this invocation's overrides and namespace resources. A command
timeout is not proof that every owned process stopped. Preserve a failed result
when cleanup or a postcondition cannot be established. Database/user/state
lifecycle outside the harness's explicit cleanup relies on disposable-runner
destruction; this is not a general host maintenance tool.

## Consequences, blast radius and reversibility

Linux network namespaces, systemd integration and administrative capability are
required. Runtime unavailability is a visible failure or unexecuted boundary,
never a passing substitute. This adds an explicit synthetic acceptance path;
package imports, ordinary tests and production startup do not create namespaces,
install services, collect live data or weaken HTTP policy.

No TLS certificate/SNI, Internet DNS, external publisher, real source quality,
production interval, sustained load, memory-pressure, reader isolation, model
quality, cloud operation or full recovery claim follows from this fixture.
Other dedicated tests and operational acceptance remain necessary. HTTP is
deliberate because TLS/public-network coverage is outside this bounded case.

Blast radius is the guarded disposable runner and its synthetic PostgreSQL
container, namespace and service resources. Disable the manual workflow or remove
the owned fixture overrides to stop using this evidence path. No application
schema or production network rollback is required. Reverting a fixture does not
invalidate prior immutable receipts, but new candidates cannot inherit a prior
successful run without checking exact source, wheel and fixture identities.

## Verification and evidence

Require an actual installed-wheel run showing enabled HTTP 200 acceptance,
timer-triggered 304 without duplicate outbox events, HTTP 503 and retained retry
delay, a non-due no-dispatch tick, and full changed-representation recovery after
failure. Check exact raw/text objects and reader-independent database heads/run
counts; verify journal UID and owned process/resource cleanup. Include negative
isolation and authentication controls before claiming these positive outcomes.

Guard/syntax tests are useful but do not establish namespace or systemd runtime
behaviour. The revision-bound manual profile receipt records executed outcomes
and runtime limitations separately from native regression CI. Until that receipt
exists for the candidate, this ADR allocates required evidence rather than
asserting the new integration has passed.
