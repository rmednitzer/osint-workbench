# ADR-0062: Opt-in bounded static HTML acquisition

Status: ACCEPTED for the bounded static-text profile. Date: 2026-10-20.

## Context and decision drivers

The public collector accepts RSS/Atom and separately configured JSON API adapters.
An ordinary static HTML document fails the feed-version check. Operators therefore
cannot use the existing evidence, conditional-request and job path for a configured
page without an external extractor whose provenance and failure rules differ.

A useful increment must preserve the existing feed identity and authority, retain
raw evidence and normalized-text coordinates, bound hostile parsing, and avoid
implicit browsing, provider adoption or source-catalogue selection. The full
acquisition roadmap, including rendered pages and restricted content, remains open.

## Alternatives, including no change

- No change: retain the feed-only path and external manual extraction gap.
- Infer an adapter from response bytes or content type: a changed source could
  silently change identity and extraction semantics; rejected.
- Fetch HTML links, canonical targets or embedded resources automatically: expands
  acquisition authority and resource/rights scope; rejected.
- Add a browser or readability dependency: requires a separate execution and
  semantic qualification boundary; deferred.
- Selected: an explicit `static-html/1` adapter within the existing collector,
  with a conservative UTF-8 HTML subset and the existing isolated-process limits.

## Decision and affected contracts

Private source configuration retains schema version 1 with the backwards-compatible
RSS/Atom default. Static HTML requires explicit `adapter: static-html/1`,
`rights: all-existing-uses-permitted` and `request_billing: unmetered`. These are
operator declarations, not independently verified legal clearance or provider facts.
The model is revalidated at collection admission, including Python callers, before
network dispatch. Existing RSS configurations and resource fingerprints stay exact.

The static parser requires a single explicit head/title and body in order, strict
UTF-8 bytes and nonempty bounded title/body text. Its exact accepted subset is in
[the runbook](../static-html-acquisition.md). Selected executable/template regions
are excluded. Character/entity decoding and whitespace extraction establish a
normalized text coordinate space; they do not establish browser visibility,
readability, article selection, prompt safety or factual support.

The child returns title and text only. The parent binds item identity to the exact
operator-configured URL, leaves publication time unknown, and records the versioned
extractor. HTML links, base/canonical declarations, dates and instructions cannot
select another acquisition, rewrite item identity or confer authority. The shared
transport still validates every public destination/redirect, pins DNS addresses,
retains TLS identity and enforces framing, byte and network deadlines.

A fresh isolated-mode process receives bytes, inherits no operator credentials,
and has the existing parser CPU/address-space/file/result/wall bounds. These are
resource limits, not a filesystem/network sandbox or protection against host root.
No browser, model, credential resolver or new dependency is loaded for extraction.

The existing per-source session lock, durable attempt/backoff, validated conditional
requests, CAS verification, lifecycle admission, item-head reconciliation and
transactional outbox remain the acceptance path. A successful parse publishes raw
and normalized bytes before accepted metadata. Failed parsing preserves earlier
accepted state and reports a fixed failure; this does not archive every failed HTTP
representation. Changing adapter invalidates validators and freshness rather than
reusing a cache interpreted under another extractor.

## Consequences and blast radius

One configured page produces one logical item. A changed raw container with
identical title/text can retain the current head and job while its successful run
retains the new raw bytes. Changed extracted content creates an immutable version;
retirement/expiry suppresses it through the existing logical key. Accepted counts
remain acquisition receipts, not completed downstream processing.

No SQL migration or grant change is needed. Collector, worker and reader identities
retain their existing capabilities; MCP remains the same seven reads. Source URLs
and raw responses remain private evidence. New extraction does not authorize cloud
release, restricted-content processing, publication or operational source collection.

## Verification and remaining uncertainty

Discriminating tests cover exact legacy resource identity; declaration and mutable
model rejection before dispatch; actual child parsing and fixed failure outcomes;
encoding, structural and output bounds; excluded content and inert URL/date
metadata; adapter-switch cache invalidation; raw-only change reuse; conditional
304, failed extraction and recovery; lifecycle suppression; chunk coordinates and
reader evidence. Installed native and explicitly disposable service checks establish
execution under their named revisions, not representative Internet interoperability.

The full roadmap still requires JavaScript rendering, broader formats, authenticated
provider contracts, shared-host quotas, restricted rights isolation, semantic
quality and operational adoption. CSS/DOM/browser repair, automatic charset
selection, inferred publication dates and general web crawling are unimplemented.

## Reversibility and rollback

Disable the static source explicitly before removing its configuration or running
an older binary. Removing configuration alone does not disable its historical row.
Older binaries cannot parse the new adapter fields. Restore an older feed-only
configuration only for intended feed sources; never reinterpret an HTML source by
silently dropping its adapter. Retained raw/snapshot/document/job history stays
immutable and readable. A protected revert can remove new dispatch support without
rewriting that evidence or any published migration.
