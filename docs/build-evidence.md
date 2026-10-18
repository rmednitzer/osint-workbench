# Build integrity evidence

`scripts/build_evidence.py` produces an offline JSON integrity receipt for the
wheel, source distribution and `uv.lock`, bound to the actual clean checked-out
commit and tree. PR runs can identify GitHub's synthetic merge commit rather than
the PR branch tip; preserve that distinction when reviewing a receipt.

The receipt records the executing CPython version, verified Ubuntu release,
explicit numeric workflow run ID and attempt, and every distribution installed in
the caller-prepared environment. It excludes filesystem paths, hostnames, user
identities, arbitrary environment variables, credentials and package contact data.
Only approved public build inputs belong in this workflow.

## Generate and verify

Run after the installed-wheel tests and publication scans. Use a dedicated
runtime plus retrieval environment, rather than the test environment containing
development dependencies. From the clean repository checkout:

```sh
uv venv /tmp/ow-evidence --python "$OW_EVIDENCE_PYTHON"
uv export --locked --extra retrieval --no-dev --no-emit-project --output-file /tmp/ow-evidence-requirements.txt > /dev/null
uv pip sync --python /tmp/ow-evidence/bin/python --require-hashes /tmp/ow-evidence-requirements.txt
uv pip install --python /tmp/ow-evidence/bin/python --no-deps dist/*.whl
export OW_EVIDENCE_COMMIT="$(git rev-parse HEAD)"
export OW_EVIDENCE_TREE="$(git rev-parse 'HEAD^{tree}')"
export OW_EVIDENCE_RUN_ID="$GITHUB_RUN_ID"
export OW_EVIDENCE_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT"
/tmp/ow-evidence/bin/python scripts/build_evidence.py generate --artifacts dist --lock uv.lock --output outputs/build-evidence
/tmp/ow-evidence/bin/python scripts/build_evidence.py verify --artifacts dist --lock uv.lock --output outputs/build-evidence
```

The caller sets `OW_EVIDENCE_PYTHON` to the selected minor version, such as `3.14`,
and `OW_EVIDENCE_OS` to `ubuntu-24.04` or `ubuntu-26.04`. The script checks these
against the running interpreter and `/etc/os-release`; it does not merely copy
those claims. Run ID and attempt must be positive integers. No network operation
occurs inside the evidence script; preparing the environment uses the locked
public package registry artifacts.

Keep the receipt outside `dist`, which must contain exactly one selected project
wheel and one source distribution. The output directory must not already exist.
Upload only those artifacts and the two receipt files after successful validation.
A later verifier needs the same source, artifact bytes and matching isolated
inventory environment to recompute the receipt.

Input reads open with no-follow and nonblocking flags, reject non-regular files
before reading, and close descriptors on every outcome. Artifact and lock reads
consume at most 256 MiB plus one refusal byte, even if a file grows after its
initial size check. Receipt reads have separate 4 MiB and 65-byte limits. Observed
size or modification-time changes during a read cause refusal; these checks do
not provide an immutable filesystem snapshot against a malicious writer.

## Limits and unresolved licensing

This is a machine-readable installed distribution inventory and integrity receipt,
not a CycloneDX or SPDX SBOM, a signature, a provenance attestation, or independent
proof that the supplied source produced the artifacts. `manifest.sha256` detects
accidental receipt changes; an attacker controlling the receipt can also replace
its checksum. Verification compares a freshly recomputed receipt against both
files. Trust in the source, runner, metadata and distribution channel remains an
explicit dependency.

License expressions and license classifiers come from publisher-declared package
metadata. They are preserved separately without resolving disagreements or
converting ambiguous classifiers into SPDX identifiers. The script accepts a
bounded safe character set but does not validate SPDX grammar or the identifier
list. It omits free-form license fields and contact data. Missing expressions
appear in `unresolved_license_expressions` and do not silently become a license
approval or a build failure. Every package still requires any applicable legal
review; a present expression is not a reviewed legal disposition.

The inventory does not cover bundled native libraries, the native test server,
container layers, operating-system packages, development/build tools, model
weights or acquisition data. A maintained SBOM generator and separate license
review remain necessary before claiming those broader outcomes. Inventory scope
also depends on correctly preparing the dedicated environment; the script cannot
infer why a distribution was installed. Remove the workflow invocation and its
receipt upload to roll back this additive evidence mechanism; application runtime
behavior and stored data are unaffected.

## CI retention and signed main builds

The foundation matrix uploads each successfully tested distribution pair and
verified receipt as a separate `build-evidence-` artifact, retained for 30 days.
A failed test or publication scan prevents that upload. PR receipts identify the
synthetic merge checkout; they are not signed main builds.

A separate job runs only after a successful push to protected main and all native
matrix legs. It downloads only this run's artifacts, does not check out or execute
repository code, and signs distributions and receipt files with the SHA-pinned
`actions/attest` action. Only that job has OIDC/attestation write permissions. Its
portable Sigstore bundle is retained separately for 30 days; public attestations
are also registered with GitHub and public Sigstore transparency infrastructure.
Those records can be permanent. Only public source/artifact identities belong in
them. Neither mechanism publishes a package release.

Verify a downloaded distribution using the GitHub CLI, and inspect the returned
source revision and workflow identity against the intended reviewed main run:

```sh
gh attestation verify downloaded.whl --repo rmednitzer/osint-workbench --signer-workflow rmednitzer/osint-workbench/.github/workflows/ci.yml --source-digest "$EXPECTED_MAIN_SHA" --source-ref refs/heads/main --deny-self-hosted-runners
```

A valid signature binds the artifact digest to the identified workflow; it does
not prove that code is vulnerability-free, that every dependency has a reviewed
licence, or that the inventory is a complete SBOM. Preserve the artifacts and
bundle elsewhere if a release needs retention longer than this CI policy.
