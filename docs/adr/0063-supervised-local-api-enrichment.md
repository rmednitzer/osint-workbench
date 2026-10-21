# ADR-0063: Bounded supervised local-API enrichment

Status: ACCEPTED for opt-in supervised execution. Date: 2026-10-21.

## Context and alternatives

Local API enrichment has explicit enqueue/work-once and durable uncertainty, but
no bounded aggregate worker or service template. No change requires an external
loop whose failure/replay and credential custody may differ. Reusing the chunk
worker would mix job kinds and authority. A generic native/cloud batch dispatcher
would broaden resource and disclosure policy. Select a local-API-only bounded tick
and separate non-root service, leaving all enqueue/review authority explicit.

## Decision and boundaries

`enrich work --local-api-manifest ... --max-jobs N` accepts 1–32 claims (default 4).
It claims only the exact configured generator identity, stops on first failure,
and reports aggregate counts without source/model/credential content. Idle is a
bounded claim observation, never an empty-queue guarantee. Successful jobs remain
committed on later failure. Failed ticks exit nonzero. Native/cloud batch selection
is refused before dispatch; work-once and explicit reconciliation remain separate.

The optional service uses a distinct account and writer login, read-only shared
evidence, a private environment/manifest and systemd-loaded bearer credential.
Its host-local inference lock and uncertainty records reside in persistent private
StateDirectory, not PrivateTmp. Stopping/restarting the unit never clears markers
or proves remote computation stopped. No automatic reconciliation, re-enqueue,
review acceptance, model download or provider fallback is introduced. The default
network allowance is loopback only; private-LAN deployment needs reviewed explicit
address allowances and the existing authenticated TLS manifest.

## Consequences, acceptance and rollback

The timer is opt-in; cadence and supervisor/resource caps are example limits,
not SLOs or model adoption. Database/schema/evidence provisioning stays explicit.
Actual weights, no-forwarding, licensing, semantic usefulness and server-side
resource isolation require independent operator qualification. A local endpoint
alone does not establish sovereignty.

Installed SQL/HTTP CLI tests cover cap, idle, exact generator scope and failure
stop. Guarded two-LTS service acceptance covers actual service identity, loaded
credential use/refusal, persistent uncertainty across restart and no redispatch.
A synthetic abstention response establishes integration, not useful inference.
Disable the new timer/service to roll back supervision; retain unresolved markers
and job/accounting records. No schema migration or prior artifact rewrite is needed.
