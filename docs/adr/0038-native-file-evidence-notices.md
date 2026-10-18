# ADR-0038: Bind recorded native-file identities and supplementary notices

Status: ACCEPTED. Date: 2026-10-18.

## Context and decision criteria

ADR-0037's Python SBOM and licence hashes do not identify the actual native
files in wheels. Identical METADATA and licence texts can accompany changed
binaries. Two reviewed wheels also omit upstream licence texts. The project
needs discriminating byte evidence and retained supplementary material without
inventing a complete component/version graph or legal approval.

Criteria are exact supported-profile identity, no execution of inspected native
code, bounded offline processing, minimal public metadata, reproducible evidence
and explicit unresolved composition. This refinement changes build assurance,
not the supported application runtime or operational deployments.

| Alternative | Consequences |
| --- | --- |
| No change | Native byte drift and missing retained texts remain unaccounted for |
| Infer components and versions from filenames or strings | May misattribute static bundles, ABI versions and upstream lineage |
| Run the inspected binaries or `ldd` | Introduces unnecessary execution and host-loader dependence |
| General scanner over complete containers/models now | Different artifact scope and larger identification/adoption work |
| Maintained ELF parser, exact wheel-file policy and separate upstream texts | Bounded evidence with explicit composition gaps; selected |

## Decision and acceptance

Review the locked standard CPython 3.12–3.14 Linux x86_64 wheel variants. Inspect
recorded installed ELF files as data with a maintained development-only parser.
Match the complete package file set and byte identities to a reviewed variant;
do not mix independently matching files from different wheel variants. Reject
unknown, missing, added or changed recorded ELF files. Preserve existing package
versions when adding the tool dependency.

Report only source/runtime/workflow binding, normalized distribution identity,
package-relative file identity, bounded ELF headers and declared SONAME/NEEDED
basenames. Omit absolute paths and raw loader-search paths. Do not import,
execute or dynamically load target modules deliberately. Ordinary interpreter
site startup still requires trusted prepared environments and startup hooks;
`-I` is not a hostile-environment sandbox. Descriptor walking refuses symlinks
beneath the trusted environment prefix; its ancestors remain caller-controlled.
Exact WHEEL tag identity does not independently establish host compatibility;
the locked installer and installed/native matrix provide that evidence.
Apply bounded regular-file reads,
child lifetime/resource limits and fixed errors. Regenerate for verification.
This scope depends on distribution records and trusted build environments;
unrecorded files and malicious same-account writers remain outside its claim.

Retain exact reviewed upstream licence text for Flatbuffers and tokenizers in
the repository and generate a deterministic separate supplement. Validate exact
versions, immutable upstream identities and text hashes. Refuse missing or
modified material and compare complete output bytes on verification. The
supplement does not alter publisher wheels or establish all applicable NOTICE,
corresponding-source, patent or redistribution obligations.

The v3 build receipt binds four supplementary files. The isolated main signer
admits exactly eight files per profile and signs their bytes as provenance
subjects after every installed/native and policy gate. Its actual inline script
must pass a synthetic complete-set case under optimization and reject changed,
missing, unsafe, oversized, incorrectly scoped or identity-mismatched inputs.
Source/artifact and private exact-value scans remain required. Historical v1/v2
receipts keep their original source and scope.

## Residual risk, impact and rollback

ELF dynamic names do not establish resolved runtime paths or library versions.
Static/Rust transitive graphs, OS/container packages, model assets and the native
test server's complete composition remain open. A notice inventory is not legal
clearance. A parser can contain defects; locked provenance, bounded processing,
negative tests and declared scope reduce rather than eliminate that risk.

Review corrected the earlier archive count: thirty standard-ABI wheels plus one
additional unsupported free-threaded archive had been inspected for licence
bytes. That extra inspection does not expand runtime support. The native policy
excludes free-threaded ABIs. Preserve that evidence distinction on future updates.

Blast radius is development tooling and public synthetic CI evidence. There is
no application/schema change, provider request, pretrained download, fleet action
or operational deployment. Roll back through a protected PR by restoring the
previous receipt/CI profile together; preserve required check names and signing
isolation. Retain old evidence as source-bound history. Reverting cannot retract
public signatures or extinguish obligations for software already distributed.
