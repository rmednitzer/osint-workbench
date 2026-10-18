# Supplementary upstream licence texts

This repository retains two exact upstream Apache-2.0 texts that are missing from
the reviewed flatbuffers 25.12.19 and tokenizers 0.23.3 wheels. The offline builder
assembles a separate `assurance/missing-wheel-notices.txt`; it does not modify,
repackage or repair either third-party wheel. This is a bounded notice supplement,
not legal approval or complete redistribution clearance.

## Exact source custody

| Distribution | Repository and immutable commit | Upstream path | Vendored source |
| --- | --- | --- | --- |
| flatbuffers 25.12.19 | `google/flatbuffers`, `7e163021e59cca4f8e1e35a7c828b5c6b7915953` | `LICENSE` | [Exact source](notices/flatbuffers-25.12.19.LICENSE) |
| tokenizers 0.23.3 | `huggingface/tokenizers`, `301277072263fb3830eb66eec7e47adadf76f1dc` | `LICENSE` | [Exact source](notices/tokenizers-0.23.3.LICENSE) |

The [review policy](dependency-licences.json) records the public immutable origin
links and SHA-256 values. Flatbuffers' source is 11358 bytes with SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`;
tokenizers' source is 11357 bytes with SHA-256
`c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`.
The different leading/trailing source bytes are retained, rather than replaced
with a generic Apache template. No copyright holder, missing NOTICE content or
additional permission is inferred from that template or its appendix.

`build_notices.py` pins both component versions and exact upstream identities.
It accepts policy schema 1 with exactly those two missing-text dispositions and
rejects missing components, a third unresolved missing-text component, duplicate
records, changed origins, hashes, versions or newly claimed shipped-text status.
A dependency update requires reviewing the new source and deliberately updating
the policy, vendored source, builder selection and tests together. Updating a hash
alone does not establish compliance.

## Offline generation and verification

Use the existing build interpreter; no dependency installation, remote requests
or upstream fetching occurs:

```sh
mkdir assurance
.venv/bin/python scripts/build_notices.py generate --policy docs/security/dependency-licences.json --output assurance/missing-wheel-notices.txt
.venv/bin/python scripts/build_notices.py verify --policy docs/security/dependency-licences.json --output assurance/missing-wheel-notices.txt
```

The output parent must already exist. Generation refuses any existing output,
including symlinks and FIFOs; it never overwrites a previous receipt. Reads reject
symlinks in directory components and nonregular final files, use nonblocking opens,
and check byte limits and metadata across each bounded read. Source bytes must
match the fixed length and hash before any output is created. Failed writes leave
an unaccepted output that must not be treated as evidence; review it privately
before removing it for a new build. Verification is read-only and compares the
entire bundle against a fresh deterministic reconstruction.

The bundle contains the policy SHA-256, fixed component identities, immutable
upstream commit/path, source byte counts/hashes and each exact source byte sequence.
Explicit section markers and separator newlines are outside those source bytes.
It adds no timestamps, local checkout paths, contacts or installed-package
metadata. The pinned upstream text remains verbatim; this mechanism does not
redact publisher notices or replace their terms with a generic template.
Changing any policy byte changes the bundle's policy binding even if the two texts
remain unchanged. The build receipt must bind the actual generated bundle, and the
bundle verifier must pass before accepting that receipt.

## Outstanding obligations and rollback

This supplement supplies only these two upstream LICENSE texts. It does not
establish that either upstream release has no applicable NOTICE, additional
copyright notices, embedded third-party terms or source requirements. In
particular, tokenizers' native Rust dependency closure remains unresolved. It does
not complete wheel/source/native/container inventories, corresponding-source or
relinking obligations, model/data licences or review of the actual redistribution
and modification method. The [dependency licence review](dependency-licences.md)
and its unresolved outcomes continue to apply. Distributing this separate file
is not evidence that an omitted file has become present in a third-party wheel.

Removing the builder or supplement rolls back this additive evidence mechanism;
it changes no runtime, database or third-party wheel. It also removes the offered
texts from future evidence bundles and does not remove obligations for previously
distributed software. Do not change unresolved policy outcomes to approved merely
because generation and verification succeed.
