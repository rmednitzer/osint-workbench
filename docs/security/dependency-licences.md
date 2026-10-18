# Dependency licence evidence and outstanding dispositions

This review accounts for the 49 installed Python distributions in the locked
runtime plus retrieval profile on 2026-10-18. It includes the Apache-2.0
application. It is an engineering inventory of declarations, shipped texts and
remaining work, **not legal approval or a redistribution clearance**.

[The machine-readable policy](dependency-licences.json) records exact versions,
publisher `License-Expression` separately from text summaries, wheel-relative
METADATA/licence paths and SHA-256 hashes. Fourteen distributions have no
`License-Expression`; that does not mean they have no licence. Twelve of those
ship relevant texts. Flatbuffers and tokenizers ship no licence text in the
reviewed wheels and remain explicitly unresolved for distribution notices.
Exact-release upstream Apache-2.0 texts were independently obtained for those
last two components and byte-hashed: Flatbuffers commit
`7e163021e59cca4f8e1e35a7c828b5c6b7915953` and tokenizers commit
`301277072263fb3830eb66eec7e47adadf76f1dc`. The JSON retains immutable public
source links and hashes. These are upstream-only dispositions; neither that
evidence nor classifiers/legacy declarations resolve missing wheel notices.

## Evidence and verification

The initial evidence comes from the hashed, no-development runtime plus retrieval
installation on CPython 3.12/Linux x86_64. Separately, 31 locked manylinux x86_64
wheels were downloaded from their exact public registry artifact URLs and
checked against `uv.lock` SHA-256 values before ZIP inspection. Thirty cover
standard CPython 3.12, 3.13 and 3.14 and compatible ABI3 tags; the remaining
ONNX Runtime archive uses the free-threaded CPython 3.13 ABI and is outside the
supported runtime profiles. Their referenced METADATA and licence-text
bytes match the initial evidence. The policy records those wheel filenames and
hashes. The additional free-threaded archive inspection does not establish runtime
support. Musl, Windows, macOS, other architectures and source builds are outside
that wheel inspection. Hashes establish byte identity, not publisher
truth, completeness of notices or legal compatibility.

`locked_wheel_sha256` lists registry candidates present in the lock, including
platforms outside this review; it is not a list of inspected artifacts. The
separate `reviewed_native_wheels` list identifies actual inspected native wheels.
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
explicit unresolved outcomes. It never means every distribution is cleared.

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
