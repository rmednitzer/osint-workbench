# Native ELF evidence boundary

This policy inventories ELF objects belonging to the 47 locked Python runtime
plus retrieval distributions on supported Linux x86_64 profiles. It adds a binary
evidence check alongside the distribution inventory, SBOM and licence-text review.
It is not a complete native dependency graph, vulnerability assessment, licence
clearance or proof of the libraries that a running process actually loads.

## What is inspected

[The policy](native-components.json) records complete per-distribution ELF-file
sets, with wheel-relative paths, sizes, SHA-256 values and parsed ELF metadata.
A variant is a whole set: the verifier must not combine individual matching files
from different variants. Installed WHEEL tags must also match the proof archive's
tags; an extension-bearing ABI3 installation cannot fall back to a universal
empty-set proof merely by losing its extension and RECORD entry. WHEEL tags are
publisher-supplied metadata, not cryptographic archive-origin proof. An empty set is also explicit, so adding a RECORD-listed
ELF object to a previously non-ELF distribution requires review. Distribution
names and versions must match the exact runtime inventory.

The current MCP 2.3.0 refresh policy contains 67 archive variants: 30
standard-ABI/ABI3 native registry wheels, 36 universal registry wheels and one
newly built application wheel. There are 147 ELF-file proof entries across these
variants; repeated files across archives remain part of each complete set. The
inspected universal protobuf wheel has an empty ELF set, while its ABI3 wheel
has an extension object. All inspected universal wheels had no ELF objects.
The frozen CPython 3.12 installation contains 50 RECORD-listed ELF files across
11 distributions, and those complete sets match the current reviewed policy.
This local byte/metadata comparison is not a hosted runtime acceptance result for
every supported Python minor.

The prior policy at source `331d597` accounted for 49 distributions and 69
archive variants (30 native registry, 38 universal registry and the application).
Its 147 native ELF proof entries remain byte-for-byte unchanged in this refresh.
Only pure-package membership, MCP/filelock versions and the application wheel
identity change; the former review remains in Git history. Package additions and
removals are listed in [the licence review](dependency-licences.md).

Wheel archive bytes are obtained from the public locked registry URLs and checked
against their `uv.lock` SHA-256 before ZIP inspection. Supported archive evidence
covers standard CPython 3.12, 3.13 and 3.14 manylinux x86_64 wheels and compatible
ABI3 wheels, plus universal wheels and the reviewed application wheel. It excludes
free-threaded, musl, Windows, macOS and other architectures. The earlier licence
review additionally inspected one unsupported CPython 3.13 free-threaded ONNX
Runtime wheel; that archive is not admitted by this native policy.

The inspection code reads bytes and parses ELF headers/dynamic entries; it does
not deliberately import, execute or dynamically load the wheel's native code and
does not run `ldd`. Ordinary Python site startup remains a trusted prerequisite,
as explained in [the native runbook](../native-inventory.md).
The observed type, machine, bit width, SONAME and DT_NEEDED names are binary
metadata, not evidence that the dependency exists, is compatible, is safe or is
resolved to a particular host file. A SONAME or version-looking filename is not
an established upstream component version. A matched ELF-set variant is evidence
of matching reviewed files, not unique proof of the original wheel archive when
several archives have identical ELF sets.

The installed check covers distribution RECORD-listed files visible in the
caller-prepared dedicated environment. It does not discover arbitrary unrecorded
files, externally installed libraries, loader environment changes, later file
replacement or files outside that inventory. Preparing and protecting the
installation remains a caller responsibility. Static libraries, statically linked
Rust/C/C++ dependencies, embedded code/data and dynamically selected plug-ins
cannot be reconstructed from ELF DT_NEEDED entries alone.

## Component observations and unresolved closure

| Distribution | Observation supported by reviewed wheel contents | Remaining boundary |
| --- | --- | --- |
| NumPy | Extension objects and separately bundled `numpy.libs` objects; its shipped licence identifies OpenBLAS, LAPACK, GCC runtime and libquadmath families | Exact bundled upstream versions, static components, corresponding source and full licence obligations are unresolved. Hashed filenames and SONAMEs are not upstream version evidence. |
| psycopg-binary | Extension objects plus separately bundled libraries with libpq, OpenSSL, Kerberos, LDAP, SASL and other library-family filenames | These are filename/ELF identity observations, not verified upstream versions or a complete dependency graph. Top-level Psycopg version/LGPL text does not resolve those libraries' notices or source obligations. |
| ONNX Runtime | Runtime/provider shared objects and a Python extension; separate shipped third-party notices are retained by the licence policy | Notice entries are not a verified component/version graph; static/provider dependencies and actual runtime loading remain unresolved. |
| cryptography, hf-xet, tokenizers, pydantic-core, rpds-py | Python extension ELF objects, including ABI3 objects where supplied | Statically linked Rust/native dependency graphs are not enumerated by this ELF inventory. |
| cffi, PyYAML, protobuf | Python extension ELF objects | Build-time/static native components and host-library resolution remain outside the observed DT_NEEDED boundary. |
| Remaining distributions, including the application | Explicit reviewed empty ELF sets where the inspected wheels contain no ELF object | An empty set does not establish absence of native dependencies in operating-system packages, subprocesses, plug-ins or optional external profiles. |

The policy deliberately does not invent native component versions from embedded
strings or library filenames. The Python distribution version identifies its
wheel package only. Resolving native vulnerabilities and distribution obligations
requires a successor review with attributable component/version evidence,
corresponding sources and the actual deployment's library resolution.

## Updating and interpreting the gate

Run the native verifier in the same isolated no-development runtime used for the
build inventory; its tooling interpreter may separately supply the maintained ELF
parser. Consult the verifier's CLI and [build evidence](../build-evidence.md) for
the integrated invocation. A successful report means the recorded ELF file sets
match an admitted variant. It preserves unresolved native-closure scope; it is
not a legal or security approval.

When a package changes, obtain its exact locked wheel, verify the archive hash,
inspect the complete ELF set and metadata, update the explicit variant and review
its notices/source obligations. Do not add a hash merely to make CI green. A new
ABI or platform requires explicit archive evidence and runtime acceptance; a
compatible-looking ELF header does not establish supported execution. Removing
this additive gate rolls back its enforcement without changing application state
or resolving obligations from already distributed binaries.
