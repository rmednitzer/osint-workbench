# Recorded native file review

`scripts/check_native.py` identifies and inspects ELF files listed in the
installed runtime plus retrieval distributions' RECORD metadata. It supplements
the [Python SBOM](sbom.md), [licence review](security/dependency-licences.md) and
[build integrity receipt](build-evidence.md). Its reviewed reference sets are in
[the native component policy](security/native-components.md).

The maintained pure-Python `pyelftools` 0.33 parser is a locked development tool;
it is not added to the runtime profile. The explicit probe/parser code does not
import inspected packages, load a shared object, run an inspected native file or
invoke a loader-discovery utility. The target probe explicitly imports only
standard-library metadata inspection and the repository's bounded file helpers.
Both interpreters still perform ordinary Python site startup: `-I` does not
suppress `.pth` or `sitecustomize` execution. The prepared interpreters, installed
site configuration and environment prefix must be trusted. This is not a safe
scanner for an arbitrary hostile Python environment.

## Generate and verify

Prepare the isolated installed runtime plus retrieval environment and initial
integrity receipt as described in the build evidence runbook. Run the generator
with the separate development-tool interpreter:

```sh
.venv/bin/python scripts/check_native.py generate --python /tmp/ow-evidence/bin/python --manifest /tmp/ow-pre-evidence/manifest.json --policy docs/security/native-components.json --output assurance/native-review.json
.venv/bin/python scripts/check_native.py verify --python /tmp/ow-evidence/bin/python --manifest /tmp/ow-pre-evidence/manifest.json --policy docs/security/native-components.json --output assurance/native-review.json
```

The actual checkout must be clean and match the receipt's commit and tree. The
probe's full Python distribution inventory, declared licence metadata, Python
patch version, implementation and Ubuntu release must match that receipt. The
report binds the same source/runtime/workflow/inventory core as the Python SBOM;
it excludes supplementary hashes from that binding to avoid recursive hashes.
A final receipt with unchanged core fields can therefore verify the same report.

Generation refuses an existing output file. Verification repeats the metadata
probe, bounded ELF inspection and complete policy matching, then compares the
entire regenerated report. The report records the exact policy hash; the policy
must also identify the current `uv.lock` hash. A dependency update requires review
of its actual wheel bytes and policy variants rather than accepting a new digest
without examination.

## Selection and public output

The probe uses RECORD entries and checks each listed file's first four bytes.
It inspects files only beneath the explicitly prepared virtual-environment prefix.
Generated text entry points may live under that prefix outside site-packages;
an ELF entry outside a safe wheel-relative package path is refused. Missing
RECORD files, ambiguous distributions, symlinks and non-regular files are refused.
Unrecorded filesystem entries are outside this inventory's scope.

The parser projects package name/version, safe package-relative file paths,
size, SHA-256, ELF type, machine, word size and validated `DT_NEEDED`/`DT_SONAME`
basenames. It omits raw RPATH/RUNPATH, build/debug paths, absolute locations,
contacts and arbitrary metadata. Temporary probe data includes the private prefix
needed for safe descriptor-relative reads; it is not published. Parser and
subprocess errors emit fixed categories rather than underlying messages or logs.

For each distribution, the complete observed ELF set must match a reviewed
variant, including exact path, size, digest and parsed metadata. The expanded
installed WHEEL tag set must equal the reference archive filename's expanded
tags. This prevents an omitted native extension from matching a universal-wheel
empty proof, and prevents mixing files from different interpreter variants.
Unknown, added, omitted or changed recorded ELF files fail the review. Legitimate
pure-Python distributions need explicit empty variants too.

`matched_variants` lists reviewed archive proofs with matching identities, not
a proven archive of origin or an independent host-compatibility decision. Several archives can contain identical native file sets. Installed
WHEEL tags are publisher metadata, not cryptographic proof of origin; locked
installation, trusted build inputs and receipt verification remain necessary.
The locked installer and mandatory installed/native matrix supply actual
interpreter/platform compatibility evidence. This helper does not independently
solve host loader or platform compatibility. The current reference policy covers
the reviewed standard Linux x86-64 profiles.
Other architectures and free-threaded interpreters require separately reviewed
variants; availability of an upstream wheel alone does not establish support.

## Bounds and residual uncertainty

Each subprocess has a 90-second wall timeout, 60 seconds of CPU, 1.5 GiB address
space and 4 MiB output-file limits. Metadata enumeration is capped at 50,000
RECORD entries and 512 ELF files. WHEEL metadata is capped at 64 KiB and 64 tags.
Native reads consume at most 256 MiB plus one refusal byte per file. Every
RECORD-relative directory component and final file beneath the prepared prefix
is opened without following symlinks. The prefix's final component is also
no-follow; ancestors above it remain caller-controlled trusted paths. Final opens
are nonblocking and checked for regular-file type before reads. Descriptors close
on successful and failing paths. Observed file size or modification-time changes
cause refusal. These checks do not create an atomic filesystem snapshot against
a malicious concurrent writer; the caller must preserve the prepared environment.

The ELF parser caps program/section headers and dynamic tags, and executes in a
separate resource-limited development interpreter. It reads dynamic metadata only;
it does not interpret machine instructions, inspect DWARF provenance or infer
versions from hashed library names. SONAMEs and needed names are declarations;
they do not establish which library a runtime loader resolves or uses.

The report explicitly leaves native dependency closure unresolved. It does not
establish static or Rust transitive composition, operating-system libraries,
container layers, model weights, the native test server, vulnerability freedom,
legal approval or complete SBOM coverage. The existing Python SBOM remains scoped
to the current 47 distribution components and retains its incomplete composition
marker. Older source-bound receipts may describe the preceding 49-component
profile; they are not current inventory evidence.

Rollback removes the native review invocation and corresponding supplementary
artifact handling. Application behavior and stored data are unaffected. Preserve
prior source-bound receipts; do not relabel them as current results.

Primary reference: [pyelftools documentation](https://github.com/eliben/pyelftools/blob/v0.33/doc/user-guide.md).
