# Bounded operational-profile verification

Tested source: `d4a1e64be1e399eb052db13f35ddcf0fc5234b81`.
The documentation successor changes no application, unit, workflow, test or
harness bytes. Later source still requires its own required checks.

Installed wheel: `osint_workbench-0.1.0.dev1-py3-none-any.whl`, SHA-256
`8bbdcd3fba91163429220c421097071bb4daf43a7a863a02614d03003c1b869f`.
All three application profiles and both service profiles recorded this same wheel.
Core 10, retrieval 4, checkpoint format 2; no migration or dependency changed.
The service fixture installs core dependencies only, without retrieval tables.

## Installed/native application suite

[Foundation run 39140321685](https://github.com/rmednitzer/osint-workbench/actions/runs/39140321685)
passed repository policy, Renovate policy, all three native profiles and the
required installed-artifact aggregate. PR build signing is intentionally not
selected; the separate main-push signing path retains its existing policy.

| Ubuntu / Python | Job | Result | Pytest elapsed |
| --- | --- | --- | --- |
| 24.04 / 3.12 | 117713251671 | 1,203 passed, zero skips | 252.88 s |
| 24.04 / 3.13 | 117713251741 | 1,203 passed, zero skips | 305.97 s |
| 26.04 / 3.14 | 117713251838 | 1,203 passed, zero skips | 289.39 s |

The installed suite uses disposable PostgreSQL 18/pgvector, actual native
HTTP/TLS/Unix transports and authored ONNX/GGUF fixtures. New regressions cover:

- Actual SDK/reader byte-budget search, assertions, document continuation and
  full briefing revalidation after citation withdrawal; additional adversarial
  Unicode/escaping/window tests preserve complete records and selectors.
- Actual native tokenizer control-token positive/negative cases and exact token
  array completion, plus generator-policy identity and capability/input refusals.
- Exact effective reader relation/column grants, inherited/PUBLIC/SET ROLE and
  delegation refusal, with normal core/optional retrieval controls.
- Explicit aggregate-health thresholds and unavailable/malformed/disabled/stale/
  error/backlog states using the real reader/database view path.
- Bounded worker cap/idle/failure behavior, including 64 exhausted claims before
  a remaining eligible job, followed by successful next-tick acceptance.
- Composed authored HTTP framing/feed parsing/collector/chunk worker, installed
  CLI checkpoint and separately exported newer policy, empty-target restore and
  fresh-process reads. Retirement suppression, evidence/chunks, job history,
  disabled-source reconciliation and denied digest/policy rollback are checked.
- Private-default versus explicit shared evidence creation, no silent permission
  repair, restrictive umask, anchored identity and named/default ACL refusal.

The composed recovery fixture uses an in-memory h11 peer; the separate service
fixture below exercises actual disconnected-namespace HTTP. Fresh processes are
not a database-server restart, full-host disaster or independent policy custody.

## Actual services and hosted security analysis

[Service run 39140321865](https://github.com/rmednitzer/osint-workbench/actions/runs/39140321865)
passed both LTS system interpreters. The [machine-readable receipt](operational-service-2026-10-18.json)
retains actual reports, job IDs, wheel digests and scope exclusions. The selected
`reference-service` profile intentionally excludes the pretrained download job.

It verifies collector HTTP/SCRAM/backoff/head reuse and supervisor behavior,
separate worker/health accounts and configuration denial, newly created object
reads with CAS/code write denial, worker authentication failure without claims,
committed chunk provenance, idle restart without duplicates, lexical service
reads, explicit health failure/recovery, accelerated activation of all three
timers and removal of owned units. Actual production timer durations and sustained
mixed workload are outside this probe.

CodeQL run `39140320998` passed both Python and Actions analysis. Python analysis
`1976129494` reported two configured-path alerts; actual SARIF and independent
caller review support their individual false-positive dispositions in
[the triage record](codeql-triage-2026-10-18.md). No query or source exclusion was
added. Local source/artifact/new-message scans with the external private policy
reported zero findings; this does not clear the historical session-link finding.

## Remaining acceptance

These results establish the bounded mechanisms and their fixture interactions.
They do not adopt a pretrained encoder/reranker/generator, establish semantic
support or independent review, select a GPU/load profile, authorize a provider,
prove an independent assistant client, configure notifications, automate backups,
establish off-host custody/expiry/full-host recovery or set operational SLO/RPO/RTO.
See [the operational gates](../operational-profile.md) and
[the implementation backlog](../implementation-backlog.md). The complete target
E01–E51 programme remains open; 1,203 passing regressions do not close every full
acceptance scenario.
