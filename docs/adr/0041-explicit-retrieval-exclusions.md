# ADR-0041: Record content-determined encoder refusals as explicit retrieval exclusions

Status: ACCEPTED for the reference retrieval profile. Date: 2026-10-18.

## Context and decision drivers

A generation build encodes every current head document and fails as a whole
when any document fails. Some failures are determined by document content
alone under a fixed encoder manifest, not by runtime availability:

- text that is only zero-width or format characters passes extraction and the
  encoder's blank check, then is erased by the tokenizer normalizer;
- documents may hold 1,000,000 code points, but the encoder accepts 200,000;
- very long or token-dense documents exceed the per-document chunk, packet or
  result bounds.

Each is reachable from ordinary collection. A single hostile or merely long
feed entry therefore prevented every future generation build, and with it
any corpus-consistent activation, until an operator retired that document.
Lexical search was unaffected, but semantic retrieval silently stayed on an
increasingly drifted generation.

Activation requires the generation's members to equal the current corpus and
every member to have vectors. Simply skipping a document would break that
equality; leaving a member without vectors is indistinguishable from an
interrupted build.

## Alternatives, including no change

- No change. Keeps the contract simple but lets one document block semantic
  index maintenance indefinitely.
- Reject such text at extraction. Tokenizer-dependent, incomplete (long
  documents are valid evidence) and it would discard acquired evidence.
- Skip the document and exclude it from the corpus digest. Hides the gap and
  lets activation claim a corpus the index does not cover.
- Record the refusal as an explicit member disposition in a new optional
  profile table, keep the member, and require each member to have either
  vectors or a recorded exclusion. This is the chosen correction.

## Decision and authority boundary

Retrieval-profile migration 4 adds `ow.retrieval_exclusions(generation_id,
document_id, reason)`, keyed to an existing member, with a fixed reason
vocabulary: `INVALID_ENCODER_INPUT`, `ENCODER_PACKET_TOO_LARGE`,
`ENCODER_INPUT_TOO_LONG`, `TOKEN_OFFSETS_UNSUPPORTED`, `ENCODER_CHUNK_LIMIT`,
`ENCODER_RESULT_LIMIT` and `INVALID_EMBEDDING_NORM` (a chunk of only unknown
tokens can pool to a zero vector, as the synthetic fixture demonstrates for
zero-width-only text). Only those encoder refusals become exclusions.
Integrity, compatibility, timeout, busy, unavailable and aggregate-limit
failures still fail the build. A generation in which every member, or more
than half of the members, would be excluded fails with
`RETRIEVAL_EXCLUSION_LIMIT`, so a wrong or incompatible encoder cannot
silently produce an almost empty index.

The writer gains SELECT and INSERT on the table; the reader sees it only
through a lifecycle-filtered view; the purger gains SELECT and DELETE so
retired-record purge removes exclusions with their members. The recorded purge
count vocabulary gains `retrieval_exclusions`; historical events without that
key remain valid. Exact core8/profile3 checkpoints are adopted with an empty
exclusion table.

Builds report `excluded_documents` and per-reason counts. Index status and
hybrid search report the active generation's `excluded_documents`, so a client
can see that semantic coverage is partial. Excluded documents remain fully
available to lexical search, evidence reads and enrichment.

## Consequences, blast radius and reversibility

A single unencodable document no longer blocks semantic index maintenance.
Coverage loss becomes visible instead of global. A source that floods the
corpus with unencodable entries can still exceed the half-corpus bound; that
is an explicit, operator-visible refusal rather than a silent degradation, and
the remedy is the existing source disable/retire controls.

Stop index builders before upgrading, then run `migrate-retrieval`. An older
binary refuses profile 4. Reverting the code requires restoring a compatible
database/object/policy set; dropping the table is not a supported rollback.
Generations built before this change remain valid with no exclusions.

## Discriminating verification

Native tests build a generation over a corpus containing a zero-width-only
document and an over-length document with the real ONNX encoder fixture. They
assert ready status, recorded reasons, activation, search coverage reporting,
lexical reachability of the excluded documents, refusal of a majority-excluded
corpus, and that runtime failures still fail the build. Purge, checkpoint and
exact profile3 adoption cases cover the new table. These establish execution
contracts, not semantic quality.
