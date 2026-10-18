# Initial CodeQL local-input triage

## Operational-profile successor

Python analysis `1976129494` at
`d4a1e64be1e399eb052db13f35ddcf0fc5234b81` reported two new path findings,
alerts 40 and 41, on private-default evidence root creation/open after the
constructor/admission refactor. Review inspected their actual SARIF flows and
every production caller, independently cross-checking the trust boundary.
Both receive only operator `OW_EVIDENCE_ROOT` from CLI startup/maintenance.
Acquired data, model output and the seven MCP schemas have no root/environment
setter; evidence names are validated digests. They were individually dismissed
as false positives for this intentional configured-root authority.

The private default still trusts operator-controlled ancestors and guards the
final admission component; it is not a filesystem sandbox. The explicit shared
creation profile adds a no-follow ancestor walk, root inode identity and anchored
ownership/group/mode/ACL checks. Neither disposition asserts that private ancestor
custody is automatically enforced. No query, source path or security setting was
excluded or weakened. Later source/configuration changes need their own review.

## Original review

Observed source: `0ebf58147b91585b40932ee051f4a39e276fcbd9`.
CodeQL setup run: `39100269005`; Python analysis: `1974880998`.
The extended remote-and-local scan raised 21 findings. Review used the actual
SARIF source-to-sink flows, callers, enforcement code and existing regression
fixtures. A scanner severity is a triage input, not proof of exploitability.

## Individual authority dispositions

| Alerts | Reported operation | Reviewed input and disposition |
| --- | --- | --- |
| 1 | Publication-policy file read | Maintainer's external `OW_PRIVATE_DENYLIST`, deliberately outside Git; no acquired-content/PR setter. Intended operator read, not path injection. New policy validation is bounded and redacted. |
| 2 | Model manifest read | Operator-only model CLI argument, not MCP/model output. Intended selector. Review additionally found a blocking FIFO/nonregular-file availability gap; this increment hardens the read and adds failure tests. |
| 3 | Evaluation input read | Operator-only CLI path; no-follow/nonblocking open, regular-file and byte limits. Intended authority, not a content-supplied filename. |
| 4–5 | Evidence-root creation/open | Operator `OW_EVIDENCE_ROOT`; evidence names are validated digests and operations are anchored to directory descriptors. Intended configured root. |
| 6 | GC journal parent open | Explicit operator journal path; private trusted parent, no-follow directory open and durable intent checks. Plan fields do not select a filesystem root. |
| 7–8 | Inference lock open/marker check | Operator `OW_INFERENCE_LOCK`; no-follow, regular-file/owner checks and uncertain-work refusal. No MCP/source/model setter. |
| 9 | Native model fixture executable hashing | Only `OW_TEST_LLAMA_BIN` from the test operator; CI fixes it to the compiled digest-verified native source fixture. |
| 10–15 | Inference marker reads/writes/reconciliation | Same operator lock configuration. No content-to-path authority transition; generic confinement would change the intended deployment contract. See separate hardening limitation below. |
| 16–17 | Local quality output/parent open | Explicit operator output directory, exclusive private creation and fixed directory-relative output names. Suite fields and model output cannot select it. |
| 18 | Purge/GC/restore input envelope reads | Four explicit operator CLI paths; no-follow/nonblocking regular-file reads, byte limits and independently supplied expected digests. Payloads cannot select their own input path. |
| 19–20 | Restore evidence-root creation/parent open | Operator environment root, directory-relative private creation after policy/schema/empty-target checks. Bundle object keys are validated digests. |
| 21 | Native fixture subprocess | Same test-only executable selector as alert 9; argv array, shell disabled, fixed/synthetic arguments, CI-provisioned native build. Intended execution authority, not command injection. |

The path-injection dispositions are false positives relative to the supported
operator/MCP boundary; the test subprocess finding is a deliberate test use.
These are per-alert decisions, not query exclusions. Future callers that delegate
these selectors to untrusted clients require a new design and fresh review.
This document records reasoning; inspect the hosted alert state separately.

## Limits and separate hardening work

Operator APIs are not filesystem sandboxes. Parents and intermediate ancestors
must be operator-controlled; `O_NOFOLLOW` on the final component does not establish
that every ancestor is safe. Same-UID malicious processes already share the
service's filesystem authority. The default sticky `/tmp` protects another UID
from replacing a service-owned lock marker, but a custom writable parent can
invalidate that assumption.

At the observed source above, inference reconciliation checked the marker with
`lstat`, then opened and removed it by path. Descriptor-based reads,
identity-aware removal and explicit parent validation required separate hardening;
this race was not closed by the path-authority dispositions. The successor
[marker/SBOM review](inference-sbom-review-2026-10-18.md) and
[host-local protocol](../inference-marker-safety.md) record that implementation
and its tests without claiming malicious same-UID isolation.

The review does not establish absence of vulnerabilities, private-data safety of
all Git history, a complete dependency/native audit, or operational deployment
acceptance. No query family is disabled and no broad source path is excluded.

## PR-only successor findings

The PR-head analysis `1974894041` at `3fe2e188dc8c842b170cdd0f9a94bb6d1513644d`
raised three additional high-severity path alerts. The alert API defaults to the
main branch: query `ref=refs/pull/5/head` and inspect the separate CodeQL security
summary, not only successful analysis jobs or the default-branch alert count.

| Alert | Actual SARIF source | Disposition and additional work |
| --- | --- | --- |
| 22 | Evidence helper's operator `--lock` argument | Intentional lock selector; CI supplies fixed `uv.lock`. Review separately found a blocking-open/growing-file robustness gap. Nonblocking/no-follow descriptor reads now validate regular files before reading and enforce an actual cumulative byte budget. Native FIFO replacement, continuous growth, mutation and receipt tests cover it. |
| 23 | External private-policy environment path | Same intentional maintainer selector as alert 1. Nonblocking/no-follow regular-file admission now also prevents invalid policy files from blocking before their byte limit. |
| 24 | Model manifest CLI/environment selector | Same intended authority as alert 2, now at the hardened descriptor open. The actual CLI and size-growth tests cover admission; no MCP/source/model setter exists. |

These are individual path-authority false-positive dispositions, distinct from
fixing the additional availability/robustness issues. Future helper changes can
create new alert identities and need fresh PR-specific review. Their resolution
must not be inferred from a clean main-branch alert list.

## Settlement evidence successor finding

The PR-head analysis for `d068b410162f8c23ae8dba64a052f217b0a8ffce` raised one
high-severity path alert on `cloud.evidence_digest` (ADR-0043).

| Alert | Actual source | Disposition |
| --- | --- | --- |
| 38 | Operator `cloud-ledger settle --evidence` CLI argument; the only caller | Intended operator selector for a private provider evidence file, the same authority as alerts 3 and 18. The read is a no-follow, nonblocking descriptor open with regular-file admission, a non-empty 64 MiB cumulative byte budget, and only the SHA-256 retained. No MCP, source, model or ledger field can select the path. Tests cover symlink, FIFO, empty, oversized and missing files. |

This is an individual path-authority false-positive disposition, not a query
exclusion. Dismissing the hosted alert remains a maintainer action.

## Reading this historical triage

The alert IDs, line numbers and 21/3-finding counts above belong to their named
analyses. Later helper and settlement findings have separate source-to-sink
reviews; this file is not an exhaustive current alert inventory. The successful
[baseline CodeQL run](https://github.com/rmednitzer/osint-workbench/actions/runs/39133727466)
at `d01f80ac88da50c9f826b1a15cb18c75bd1db75f` does not itself demonstrate zero
open alerts or authorize blanket dismissal. Preserve each alert's actual
revision, authority setter and independently reviewed disposition.
