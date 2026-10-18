# Python profile SBOM

The foundation builds use the maintained CycloneDX Python generator, locked as
`cyclonedx-bom` 7.5.0, to describe each actual installed runtime plus retrieval
profile in CycloneDX 1.7 JSON. The generator executes in the development tool
environment and inspects the dedicated runtime environment. Its own dependencies
are not silently added to the runtime profile inventory.

This supplements [build integrity evidence](build-evidence.md); the older plain
inventory remains useful for exact installed metadata and licence review. Neither
an SBOM nor a valid signature establishes absence of vulnerabilities or legal
approval.

## Generate, bind and verify

Prepare the no-development-dependencies environment and an initial integrity
receipt as described in the build evidence runbook. The receipt must identify
the actual clean checked-out commit and tree, the runtime and workflow. The
initial receipt may live outside the final evidence directory to avoid a hash
cycle when the final receipt also hashes its supplementary reports.

```sh
/tmp/ow-evidence/bin/python scripts/build_evidence.py generate --artifacts dist --output /tmp/ow-pre-evidence
.venv/bin/python scripts/check_sbom.py generate --python /tmp/ow-evidence/bin/python --manifest /tmp/ow-pre-evidence/manifest.json --output assurance/sbom.cdx.json
.venv/bin/python scripts/check_sbom.py verify --python /tmp/ow-evidence/bin/python --manifest /tmp/ow-pre-evidence/manifest.json --output assurance/sbom.cdx.json
```

The generating interpreter needs the locked development dependencies. The target
interpreter needs only the installed application and its locked runtime plus
retrieval closure. The script's target probe imports standard-library package
metadata and the repository's standard-library inventory helper; that explicit
probe does not import application, inference or database client modules. Both interpreters must
belong to the explicitly prepared public build environments. Python startup and
the maintained generator may evaluate installed site configuration; this is not
a safe scanner for arbitrary untrusted virtual environments.

The target's exact distribution inventory, publisher licence metadata, Python
patch version, implementation and Ubuntu release must match the initial receipt.
The source commit and tree must still match the clean checkout. The public SBOM
records source, runtime and run identities plus a SHA-256 binding over the
receipt's `source`, `runtime`, `workflow` and `inventory` fields. Supplementary
report hashes are excluded from that binding to avoid recursion. A final receipt
with those four fields unchanged can therefore verify the same SBOM. Changing
source, runtime, workflow or inventory requires regenerating the SBOM.

Generation delegates to the stable `cyclonedx-py environment` CLI with
`--pyproject pyproject.toml --spec-version 1.7 --output-reproducible
--short-PURLs --validate`. Verification reruns that generator, regenerates the
public projection and compares the complete resulting document. Unknown or
missing component references, omitted graph nodes and inventory drift fail
closed. Valid JSON and schema validity alone do not detect removed valid edges;
the regeneration comparison provides that additional check.

The output path must not already exist during generation. Temporary raw metadata
is not retained as a public artifact. Child processes have a 60-second timeout
and 4 MiB output-file limit. Published inputs are read through the bounded
nonblocking regular-file reader used by build integrity evidence. That reader
guards the final component; trusted parent directories and workspace custody
through generation and verification remain required. No registry,
model or acquisition request is part of this generation or validation procedure;
initial installation of the locked tool and target environments is a separate
public registry operation.

## Public metadata and validation

The maintained generator supplies components and dependency relationships. A
small repository projection retains normalized package identities, versions,
public Python package URLs, recognized SPDX licence identifiers/expressions and
the generated edges. The locally built application has an application URN and no
asserted PyPI publication URL. The projection removes arbitrary authors,
contacts, descriptions, metadata properties, filesystem locations, download
qualifiers, external links and licence text. Ambiguous licence names are marked
unresolved; they are not converted into a guessed SPDX licence or an approval.
The separate [licence dispositions](security/dependency-licences.md) retain the
reviewed boundary.

Validation uses `JsonStrictValidator` from the locked CycloneDX Python library.
Its schemas and referenced SPDX/JSON-signature/cryptography resources are bundled
locally. No remote JSON Schema resolver is installed. Every generation also
requires an intentionally malformed version field to fail the same validator.
Tests cover that negative control, unknown schema properties, missing/dangling
graph references, source binding, graph tampering and removal of private metadata.

The generator's environment graph connects declared requirements to installed
target distributions. Version 7.5.0 does not evaluate each requirement's marker
or extra when selecting those edges. Treat them as a conservative declared
requirement graph for the exact installed profile, not proof of active extras,
import reachability or runtime calls. The document explicitly marks the overall
application composition incomplete.

## Boundaries and rollback

The profile SBOM covers Python distribution metadata. It does not enumerate
native libraries bundled inside wheels, the native test server, operating-system
packages, container layers, development/build dependencies, model weights or
acquisition data. Complete native/OS/model supply-chain coverage and legal
clearance remain separate work. The graph does not establish whether a component
is exploitable in this application.

If a build workflow signs these JSON bytes with its provenance job, that is
provenance signing of the SBOM file. It is not a separate CycloneDX SBOM predicate
attestation. Review the exact workflow/source identity and receipt digest; do not
infer a package release from retained CI artifacts.

Rollback removes the generator invocation and supplementary artifact handling;
application behavior and stored data remain unchanged. Remove the development
tool dependency only with a reviewed lockfile update. Retain source-bound prior
receipts rather than relabeling them as current evidence.

Primary references: [generator usage](https://github.com/CycloneDX/cyclonedx-python/blob/v7.5.0/docs/usage.rst),
[generator implementation](https://github.com/CycloneDX/cyclonedx-python/blob/v7.5.0/cyclonedx_py/_internal/environment.py)
and [CycloneDX Python library](https://github.com/CycloneDX/cyclonedx-python-lib).

The successor [native ELF inventory](native-inventory.md) is a separate report,
not additional verified component/version nodes in this Python SBOM. It records
exact observed files and declared dynamic names while retaining incomplete
composition. The v3 build receipt binds that report and the
[two-package notice supplement](security/supplementary-notices.md) alongside the
Python SBOM and licence review. Their presence does not change the graph's
marker/extra limitations or clear native/OS/model redistribution obligations.
