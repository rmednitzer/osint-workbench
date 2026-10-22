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
development dependencies. Create an empty `assurance` directory before these
commands; report generation refuses existing files. From the clean repository
checkout:

```sh
uv venv /tmp/ow-evidence --python "$OW_EVIDENCE_PYTHON"
uv export --locked --extra retrieval --no-dev --no-emit-project --output-file /tmp/ow-evidence-requirements.txt > /dev/null
uv pip sync --python /tmp/ow-evidence/bin/python --require-hashes /tmp/ow-evidence-requirements.txt
uv pip install --python /tmp/ow-evidence/bin/python --no-deps dist/*.whl
export OW_EVIDENCE_COMMIT="$(git rev-parse HEAD)"
export OW_EVIDENCE_TREE="$(git rev-parse 'HEAD^{tree}')"
export OW_EVIDENCE_RUN_ID="$GITHUB_RUN_ID"
export OW_EVIDENCE_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT"
/tmp/ow-evidence/bin/python scripts/build_evidence.py generate --artifacts dist --output /tmp/ow-pre-evidence
.venv/bin/python scripts/check_sbom.py generate --python /tmp/ow-evidence/bin/python --manifest /tmp/ow-pre-evidence/manifest.json --output assurance/sbom.cdx.json
/tmp/ow-evidence/bin/python scripts/check_licences.py --policy docs/security/dependency-licences.json --output assurance/licence-review.json
.venv/bin/python scripts/check_native.py generate --python /tmp/ow-evidence/bin/python --manifest /tmp/ow-pre-evidence/manifest.json --policy docs/security/native-components.json --output assurance/native-review.json
/tmp/ow-evidence/bin/python scripts/build_notices.py generate --policy docs/security/dependency-licences.json --output assurance/missing-wheel-notices.txt
/tmp/ow-evidence/bin/python scripts/build_evidence.py generate --artifacts dist --supplements assurance --output outputs/build-evidence
/tmp/ow-evidence/bin/python scripts/build_evidence.py verify --artifacts dist --supplements assurance --output outputs/build-evidence
.venv/bin/python scripts/check_sbom.py verify --python /tmp/ow-evidence/bin/python --manifest outputs/build-evidence/manifest.json --output assurance/sbom.cdx.json
.venv/bin/python scripts/check_native.py verify --python /tmp/ow-evidence/bin/python --manifest outputs/build-evidence/manifest.json --policy docs/security/native-components.json --output assurance/native-review.json
/tmp/ow-evidence/bin/python scripts/build_notices.py verify --policy docs/security/dependency-licences.json --output assurance/missing-wheel-notices.txt
.venv/bin/python scripts/check_publication.py --evidence assurance --evidence outputs/build-evidence
```

The caller sets `OW_EVIDENCE_PYTHON` to the selected minor version, such as `3.14`,
and `OW_EVIDENCE_OS` to `ubuntu-24.04` or `ubuntu-26.04`. The script checks these
against the running interpreter and `/etc/os-release`; it does not merely copy
those claims. Run ID and attempt must be positive integers. No network operation
occurs inside the evidence script; preparing the environment uses the locked
public package registry artifacts.

Keep the receipt outside `dist`, which must contain exactly one selected project
wheel and one source distribution. The output directory must not already exist.
The v3 final receipt requires exactly `sbom.cdx.json`, `licence-review.json`,
`native-review.json` and `missing-wheel-notices.txt` when `--supplements` is
supplied and binds their sizes and SHA-256 hashes in `related_evidence`. It
labels that profile `python-sbom-native-and-notices`;
omitting supplements produces an `integrity-only` provisional receipt. The
supplement files remain in their own directory. Upload the distribution pair,
two final receipt files and four supplementary files after successful validation.
A later verifier needs the same source, artifact bytes and matching isolated
inventory environment to recompute the receipt. Supplement hashes bind observed
bytes; they do not replace each producer's semantic verification or protect files
against later replacement. Keep the build workspace and evidence under trusted
custody from generation through scanning, hashing and upload.

Input reads guard the final path component with no-follow and nonblocking flags,
reject non-regular files before reading, and close descriptors on every outcome. Artifact and lock reads
consume at most 256 MiB plus one refusal byte, even if a file grows after its
initial size check. Receipt and supplementary file reads have a 4 MiB limit; the
checksum limit is 65 bytes. Observed
size or modification-time changes during a read cause refusal; these checks do
not provide an immutable filesystem snapshot against a malicious writer. Parent
directories remain caller-trusted, including the parents used to create the
receipt directory; this helper does not walk every ancestor with no-follow opens.

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
weights or acquisition data. The separately verified [CycloneDX Python SBOM](sbom.md) and
[licence evidence policy](security/dependency-licences.md) add bounded Python
profile coverage. The [native inventory](native-inventory.md) adds exact
recorded ELF-file identity and declared dynamic names; it does not resolve the
complete native component graph. The [notice supplement](security/supplementary-notices.md)
supplies two separately retained upstream licence texts. All these mechanisms
explicitly retain incomplete native/OS/model composition
and unresolved redistribution obligations. They do not close those broader outcomes. Inventory scope
also depends on correctly preparing the dedicated environment; the script cannot
infer why a distribution was installed. Remove the workflow invocation and its
receipt upload to roll back this additive evidence mechanism; application runtime
behavior and stored data are unaffected.

## CI retention and signed main builds

The foundation matrix uploads each successfully tested distribution pair and
verified v3 receipt and four supplementary files as a separate `build-evidence-` artifact, retained for 30 days.
A failed test or publication scan prevents that upload. PR receipts identify the
synthetic merge checkout; they are not signed main builds.

A separate job runs only after a successful push to protected main and all native
matrix legs. It downloads only this run's artifacts, does not check out or execute
repository code, and signs distributions, receipt files and supplementary file bytes with the SHA-pinned
`actions/attest` action. Only that job has OIDC/attestation write permissions. Its
portable Sigstore bundle is retained separately for 30 days; public attestations
are also registered with GitHub and public Sigstore transparency infrastructure.
Those records can be permanent. Only public source/artifact identities belong in
them. Neither mechanism publishes a package release. Signing the SBOM JSON with this
provenance predicate is not a separate CycloneDX SBOM-predicate attestation.
Historical v1 and v2 receipts retain their original scope and source; v3 does
not retroactively attach reports to older builds.

Verify a downloaded distribution using the GitHub CLI, and inspect the returned
source revision and workflow identity against the intended reviewed main run:

```sh
gh attestation verify downloaded.whl --repo rmednitzer/osint-workbench --signer-workflow rmednitzer/osint-workbench/.github/workflows/ci.yml --source-digest "$EXPECTED_MAIN_SHA" --source-ref refs/heads/main --deny-self-hosted-runners
```

A valid signature binds the artifact digest to the identified workflow; it does
not prove that code is vulnerability-free, that every dependency has a reviewed
licence, or that the inventory is a complete SBOM. Preserve the artifacts and
bundle elsewhere if a release needs retention longer than this CI policy.


## Verify a downloaded complete build

Use a trusted reviewed main commit and workflow run identity obtained independently
of the downloaded manifest. Download the two `build-evidence-` artifacts into one
private directory and the `build-attestation-` artifact into a separate directory.
Do not extract arbitrary archives into an operational directory.

```sh
python3 scripts/verify_download.py --evidence downloaded/evidence \
  --bundle-directory downloaded/signature --source-sha "$EXPECTED_MAIN_SHA" \
  --run-id "$EXPECTED_RUN_ID" --run-attempt "$EXPECTED_RUN_ATTEMPT"
```

The standard-library consumer requires GitHub CLI with attestation verification
support. It checks both exact LTS profiles, the v3 set, source/run identity and
all distribution/supplementary bytes. It invokes the cryptographic verifier with
an exact repository, workflow, main ref, source digest, signer digest and hosted
runner requirement. It verifies private snapshots of manifests and the bundle;
input files must remain under the consumer's custody through later installation.
No downloaded file is imported or executed. Extra files, nonregular/symlink inputs,
wrong identities, verifier failures and changed bytes refuse acceptance.

The downstream `verify-download` job exercises this same command on each signed
main build. It has read permissions only and executes separately from the signer;
the signer continues to execute no repository code. PRs run synthetic refusal
cases; they have no signing authority. A successful command verifies integrity
and provenance under the selected trust roots, not application safety, licence
clearance or complete programme acceptance. This adds no package release or live
deployment. Missing or failed verification must be investigated before consuming
an artifact. Roll back through a protected PR while preserving signer isolation.


## Immutable distribution continuity

The reusable installed-profile workflow builds distributions in a dedicated job
and uploads them before test code executes. Test jobs download that immutable
same-run artifact. A fresh runner compares the retained post-test distributions
and receipt hashes against the original artifact; replacement fails the required
installed-artifact check even if test code rewrites its local receipt. Main-push
signing separately downloads the originals and repeats the byte comparison.
No repository code runs in either comparison job. This binds distribution bytes
across the workflow; it does not prove the honesty or completeness of tests.
