# Inference and Python SBOM review — 2026-10-18

Reviewed implementation: `1c4ecbed6171a96583aeb810ac6c202bf87d04ad`, tree
`6a27fe68540005a1dd7f8b3e74906f8d02372c36`, PR #6. This note records review
and local evidence, not a claim that pending hosted/native jobs passed. Preserve
the earlier [CodeQL triage](codeql-triage-2026-10-18.md) as historical evidence.

## Findings and fixes

Independent marker review found no blocking regression within the documented
cooperative-account, host-local Linux contract. The implementation closes the
earlier marker-custody follow-up with descriptor anchoring, safe custody,
bounded strict receipts and conservative process liveness. Same-UID rename races,
mount administration and cross-host coordination remain outside its isolation
claim. PID-reuse branch tests substitute start-token observations; they do not
demonstrate actual kernel PID reuse.

Independent evidence review found a policy downgrade: metadata-only evidence
could still claim a shipped licence text. The helper now requires actual text
and exactly one installed METADATA entry in every complete shipped-text variant.
Eleven additional negative tests discriminate stripping, relabeling and invalid
alternative variants. Fixed-category handling covers malformed SBOM structures;
the signer additionally compares run ID/attempt and each leg's runtime identity.
These are distinct from the path-authority findings below.

## New CodeQL path flows

The extended Python SARIF analysis `1975031756` inspected the implementation
revision above; Actions analysis `1975031076` reported no results. Actual Python
source-to-sink flows were retrieved, rather than inferring an empty result from
the analysis job status or default-branch alert list. Eight new
`py/path-injection` alerts were reviewed individually:

| Alert | Sink in reviewed revision | Authority and guards supporting false-positive disposition |
| --- | --- | --- |
| 27 | `scripts/check_licences.py:30` | Explicit local `--policy` operator input to a no-follow/nonblocking, bounded regular-file read; no remote/MCP path setter; emitted report excludes arbitrary policy content |
| 28 | `inference_state.py:154` | Operator `OW_INFERENCE_LOCK`, single basename, anchored directory and no-follow stat; named identity must match held lock |
| 29 | `inference_state.py:164` | Anchored basename no-follow existence check only refuses work; unsafe markers are not adopted |
| 30 | `inference_state.py:176` | Anchored no-follow/nonblocking receipt read; UID, type, mode, single link, byte bounds and strict fields checked |
| 31 | `inference_state.py:187` | Anchored no-follow post-read stat verifies current entry against opened identity and metadata |
| 32 | `inference_state.py:209` | Anchored basename, exclusive no-follow creation with validated receipt, private file custody, fsync and readback |
| 33 | `inference_state.py:237` | Anchored basename unlink after observed receipt identity/bytes match; no malicious same-UID isolation claim |
| 34 | `inference_state.py:250` | Anchored basename, nontruncating no-follow/nonblocking lock open, safe file custody and exclusive flock |

All seven runtime flows originate in explicit operator environment configuration.
`_parent` checks absolute paths, traversal bounds, each directory component and
custody before returning the descriptor. No acquired data, prompt, model output
or MCP caller selects that configuration. This does not mean environment values
are universally safe: a future lower-trust setter changes the analysis. Record
individual alert dispositions; do not disable the query or ignore entire files.

## Local evidence and limits

Focused marker/encoder checks passed, including forty new local cases; two added
native Unix generation cases require the installed/native hosted gate because
this workspace denies Unix socket creation. The receipt/licence/SBOM focused
group passed 46 cases. Ruff formatting/lint, four-module type/security checks and
their actual negative controls passed. Source, wheel/sdist and new-commit scans
passed with the external private exact-value policy.

The newly built installed runtime profile completed provisional receipt, strict
CycloneDX generation, 49-distribution licence review, final v2 receipt generation
and verification, and SBOM regeneration against the final receipt. This local
diagnostic used run ID/attempt `1`, not a hosted-run claim. All four generated
JSON/checksum files passed the private/publication-content scan. Synthetic
six-file signer fixtures passed under Python optimization and refused changed
supplement bytes and wrong run identity. This does not constitute a signature.

Hosted acceptance and actual protected-main signatures must be inspected at
their exact revision. Python graph edges remain conservative declared metadata;
native/OS/model composition, missing wheel notices, full redistribution review
and programme-wide acceptance remain open. See [SBOM scope](../sbom.md),
[licence dispositions](../security/dependency-licences.md) and
[marker recovery](../inference-marker-safety.md).

## Successor evidence scope

Pending-job language and all counts above describe the PR #6 review point.
Later protected CI completed, including the successful
[foundation baseline run](https://github.com/rmednitzer/osint-workbench/actions/runs/39133727926)
at `d01f80ac88da50c9f826b1a15cb18c75bd1db75f`. That later run does not relabel
this local diagnostic as hosted evidence. Its 49-distribution inventory, v2
receipt, two supplements and six-file signer fixture retain their historical
scope. Current v3 receipts bind four supplementary files in an eight-file set;
the updated runtime inventory has 47 distributions. See [build evidence](../build-evidence.md),
[native inventory](../native-inventory.md) and [licence review](../security/dependency-licences.md).
Missing texts are supplied separately by the bounded notice supplement; it does
not repair third-party wheels or clear the unresolved native/redistribution obligations.
