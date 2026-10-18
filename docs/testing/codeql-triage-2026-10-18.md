# Initial CodeQL local-input triage

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

Inference reconciliation currently checks the marker with `lstat`, then opens
and removes it by path. Descriptor-based marker reads, identity-aware removal
and explicit trusted-parent validation need a separately bounded change with
symlink/rename tests. This potential race is distinct from CodeQL's reported
environment-to-path flows and is not closed by their disposition.

The review does not establish absence of vulnerabilities, private-data safety of
all Git history, a complete dependency/native audit, or operational deployment
acceptance. No query family is disabled and no broad source path is excluded.
