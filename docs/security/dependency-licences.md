# Dependency licence evidence and outstanding dispositions

This review accounts for the 47 installed Python distributions in the locked
runtime plus retrieval profile on 2026-10-18. It includes the Apache-2.0
application. It is an engineering inventory of declarations, shipped texts and
remaining work, **not legal approval or a redistribution clearance**.

[The machine-readable policy](dependency-licences.json) records exact versions,
publisher `License-Expression` separately from text summaries, wheel-relative
METADATA/licence paths and SHA-256 hashes. Twelve distributions have no
`License-Expression`; that does not mean they have no licence. Ten of those
ship relevant texts. Flatbuffers and tokenizers ship no licence text in the
reviewed wheels and remain explicitly unresolved for distribution notices.
Exact-release upstream Apache-2.0 texts were independently obtained for those
last two components and byte-hashed: Flatbuffers commit
`7e163021e59cca4f8e1e35a7c828b5c6b7915953` and tokenizers commit
`301277072263fb3830eb66eec7e47adadf76f1dc`. The JSON retains immutable public
source links and hashes. These are upstream-only dispositions; neither that
evidence nor classifiers/legacy declarations resolve missing wheel notices.

## Evidence and verification

The current MCP 2.3.0 refresh uses a newly built application wheel and frozen,
no-development runtime plus retrieval installation on CPython 3.12/Linux x86_64.
It reviews 67 archives: 30 standard-ABI/compatible-ABI3 manylinux x86_64 native
registry wheels, 36 universal registry wheels and the application wheel. Every
registry archive was rechecked against the current lock's SHA-256 before
inspection. All supported archive METADATA/licence evidence sets agree with the
installed proofs; the policy records 116 referenced files and exact reviewed
archive identities.

Compared with the prior 49-distribution review at source `331d597`, MCP changes
from 1.30.0 to 2.3.0 and filelock from 4.2.1 to 4.2.2. New dependencies are
mcp-types 2.3.0 (shipped MIT text, no `License-Expression`) and opentelemetry-api
1.45.1 (declared and shipped Apache-2.0). MCP and filelock licence-text bytes are
unchanged. HTTPX 0.28.1, httpx-sse, pydantic-settings and python-dotenv leave this
closure; the distinct HTTPX2 distribution remains. Their old review is retained
in Git history, not represented as a current installed dependency. The exact two
upstream-only notice supplements and unresolved native obligations remain.

The subsequent scheduled lock refresh replaces Starlette 1.8.0 with 1.9.0.
The selected universal wheel's locked SHA-256 was verified before inspecting its
METADATA and complete shipped BSD-3-Clause licence. Its declared expression,
Python minimum (3.11), dependency requirements and licence-text bytes are unchanged;
the version-bearing METADATA bytes change. The exact archive and evidence records
are updated; the distribution and archive counts above remain unchanged. The
[upstream release](https://github.com/Kludex/starlette/releases/tag/1.9.0)
changes TestClient streaming/cancellation and URL, header and host handling.
Compatibility remains subject to the required installed/native CI profiles.
This review does not close any existing notice or native-closure disposition.

Historically, the initial review inspected 31 manylinux archives: 30 supported
standard/ABI3 archives and one additional unsupported free-threaded CPython 3.13
ONNX Runtime archive. The current review admits only the 30 supported native
archives. No free-threaded, musl, Windows, macOS, other architecture or source-build
support follows from those inspections. Hashes establish byte identity, not
publisher truth, completeness of notices or legal compatibility.

`locked_wheel_sha256` lists registry candidates present in the lock, including
platforms outside this review; it is not a list of inspected artifacts. The
separate `reviewed_native_wheels` list identifies current inspected native wheels;
`reviewed_archives` also accounts for universal and application archives.
The application's recorded wheel hash identifies the baseline used for review;
future builds can change application code while preserving its licence evidence.
The build receipt separately binds each actual build artifact.

Run with the dedicated runtime interpreter, not an environment containing test
or SBOM-generation tools:

```sh
/tmp/ow-evidence/bin/python scripts/check_licences.py --policy docs/security/dependency-licences.json --output assurance/licence-review.json
```

The output parent must already exist and the file must not exist. The verifier
requires the exact distribution set and versions, publisher expressions, and a
complete matching reviewed set of METADATA/licence hashes. An upgrade, missing
file, changed text or additional distribution fails. A deliberate policy update
requires reinspection. If future platform evidence differs, add a complete
reviewed variant rather than combining individual matching files across wheels.
The report emits only fixed scope/status fields, package names/versions and policy
hash; it does not copy contacts, full licence texts, paths or arbitrary metadata.
A zero exit means the exact installed evidence is accounted for, including its
explicit unresolved outcomes. It never means every distribution is cleared. Input
reads refuse final-component symlinks and nonregular files and are byte bounded;
the operator must protect parent directories and the environment throughout the
check. The output uses exclusive creation but does not establish parent-directory
custody or an atomic snapshot of every inspected file.

## Conditions requiring action

| Evidence family | Engineering disposition before redistribution or modification |
| --- | --- |
| MIT, MIT-0, BSD variants, ISC-like or zlib notices within included texts | Preserve the applicable notices and disclaimers; inspect each actual text for endorsement, attribution and modification conditions. Do not replace them with the application's Apache licence. |
| Apache-2.0 application and dependencies; dual Apache/BSD packages | Retain the licence and applicable notices, record modifications where required, and carry any applicable NOTICE material. Review patent and chosen dual-licence terms. A top-level expression does not establish the terms of embedded components. |
| PSF-2.0 declarations in feedparser-sgmllib and typing-extensions | Preserve their shipped licence terms and notices; review modification/redistribution conditions from those texts. |
| certifi 2026.7.22 | The shipped notice identifies Mozilla-derived CA data under MPL-2.0. Preserve its notice and review covered-file/source-availability obligations, especially for modified bundles. This review does not authenticate the certificate data. |
| tqdm 4.70.1 | Its shipped LICENCE distinguishes MPL-2.0 and MIT contributions. Preserve that distinction and review covered-file/source-availability obligations; do not flatten it to MIT. |
| psycopg and psycopg-binary 3.3.6 | Both declare LGPL-3.0-only and ship LGPLv3 text. Review incorporated GPLv3 terms, corresponding source, replacement/relinking and reverse-engineering conditions for the actual distribution method. Do not infer that a binary wheel has satisfied these obligations merely because it contains this text. |
| Flatbuffers 25.12.19 and tokenizers 0.23.3 | Missing shipped licence text remains an explicit notice gap. Exact-release upstream Apache-2.0 evidence is recorded; arrange appropriate notices before redistributing those wheel contents. Upstream evidence alone cannot make a missing wheel file present. |

## Native bundles remain a separate unresolved boundary

NumPy's main shipped licence explicitly identifies OpenBLAS (BSD-3-Clause),
LAPACK (BSD-3-Clause-Open-MPI), GCC runtime
(GPL-3.0-or-later WITH GCC-exception-3.1), and libquadmath
(LGPL-2.1-or-later). These are additional to the package metadata's composite
expression. Its component licence files and main notice are hashed, but the
precise bundled versions, corresponding source and all applicable distribution
conditions are not resolved by this review.

ONNX Runtime ships an MIT licence and a substantial `ThirdPartyNotices.txt`;
both are hashed. That notice is not a verified component/version graph or proof
that every native component is covered. Psycopg's binary wheel can include libpq,
OpenSSL and other native dependencies whose exact closure and notices need a
separate audit. Tokenizers and hf-xet include native Rust code; cryptography,
cffi, protobuf, pydantic-core, rpds-py and PyYAML likewise require inspection of
their native/bundled dependency boundary. The JSON marks these explicitly
`unresolved-transitive-native-closure`, even when a top-level licence is clear.

Before distributing a combined binary/container, identify its actual native
libraries and versions, collect applicable source/notice material, and obtain a
review of the concrete distribution/modification method. This policy does not
review operating-system/container packages, PostgreSQL, development/build tools,
model weights, datasets or acquisition content. Nor does `not-assessed-as-native-bundle`
prove a distribution contains only Python or has no transitive obligations.

The SBOM, build inventory and this review answer different questions. Preserve
all three and their unresolved outcomes. Removing this additive gate and receipt
rolls back its enforcement; it changes no application runtime or stored data and
does not remove obligations associated with software already distributed.

The successor [native policy](native-components.md) pins supported recorded ELF
file sets and exposes declared dynamic names; it does not close the transitive
native obligations above. [Supplementary notices](supplementary-notices.md)
retain the exact two upstream texts separately. Those files supplement this
project's source and retained evidence; they do not modify the publisher wheels
or establish that all applicable NOTICE/source material has been collected.
