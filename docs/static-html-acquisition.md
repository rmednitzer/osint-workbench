# Bounded static HTML acquisition

The opt-in `static-html/1` source adapter acquires one configured public HTTP(S)
page through the existing `collect` command. It extracts syntactic UTF-8 title/body
text in a bounded child process and retains successful raw HTML as evidence.
[ADR-0062](adr/0062-bounded-static-html-acquisition.md) records the decision and
rollback. See [scheduled acquisition](scheduled-acquisition.md) for the shared
request, schedule, backoff, conditional-cache and lifecycle rules.

## Configuration and authority

Keep the configuration outside Git. The bundled source list remains empty. This
synthetic disabled example grants no real source or provider acceptance:

```json
{
  "schema_version": 1,
  "sources": [{
    "source_id": "synthetic-page",
    "url": "https://example.invalid/page",
    "adapter": "static-html/1",
    "rights": "all-existing-uses-permitted",
    "request_billing": "unmetered",
    "enabled": false,
    "poll_seconds": 900,
    "freshness_seconds": 86400
  }]
}
```

Review the actual source's permitted retention, processing and existing read/export
uses before declaring rights. The application cannot independently verify that
statement. Restricted-content isolation and paid-request accounting are outside
this adapter. Use the separately qualified API profile for supported managed
credentials; this adapter adds no authentication headers or browser session.

Set `OW_COLLECTOR_DSN` and `OW_EVIDENCE_ROOT` privately and use the ordinary bounded
tick after deliberately configuring and enabling the intended source:

```sh
osint-workbench collect --config private/sources.json --due-only --max-sources 32
```

RSS/Atom remains the default adapter for existing source entries. A format change
must be explicit. The URL is the logical item's external identity; HTML-provided
links, base/canonical metadata and dates do not alter it. No embedded resource,
link or model is fetched by the parser. The transport may follow only its existing
bounded, validated HTTP redirects; redirected representations cannot seed the
configured URL's conditional cache.

## Extraction and evidence

Input must be strict UTF-8 HTML with one explicit head containing one title,
followed by one explicit body. Missing, duplicate or out-of-order structural
regions, self-closing non-void elements, unsupported declarations and empty/oversized output fail with bounded
codes. This deliberately accepts less than a browser's repaired DOM. Publication
time remains unknown; document metadata and the origin Date header do not infer it.

Extraction removes script, style, iframe, object and template regions and ignores
head metadata. It decodes character references and normalizes text whitespace.
It does not evaluate CSS, hidden attributes, layout, JavaScript, semantic article
boundaries or instruction trust. Returned prose remains untrusted source content.
Evidence spans and downstream chunk offsets address the exact retained normalized
text, not raw HTML byte offsets or browser-rendered text.

The existing 10 MiB fetch bound and 30-second network deadline apply. Parsing uses
a fresh isolated-mode child with three CPU seconds, 512 MiB address-space limit,
32 file descriptors, 16 MiB result/file limit and eight-second parent wall timeout.
The document title and normalized text retain the application bounds. Child
resource limits do not establish a filesystem/network sandbox.

On successful acceptance, collection run evidence references the original HTML
bytes and document/snapshot evidence binds their hash, normalized text and extractor.
Raw-only changes can reuse the current item's normalized content and existing job;
the successful run still preserves its newly fetched raw representation. Changed
title or body produces a new version. A validated 304 retains the existing raw
hash and reports zero newly accepted documents. None of these acquisition counts
proves chunking, enrichment or end-to-end pipeline completion.

Parsing failure leaves the earlier accepted head and last success intact, records
a bounded failed run and backoff, and requires a full subsequent response. It does
not retain every invalid HTTP representation. Missing/corrupt cached evidence is
still an explicit recovery problem; a different response cannot silently repair it.
Retirement and expiry suppress acceptance through the existing logical key.

## Operation and rollback

The existing collector service can read the same private source configuration;
account, shared-evidence custody and supervision still require explicit provisioning.
Use the [deployment procedure](deployment.md) and scoped collector credential.
Neither configuration nor package installation starts a service or live collection.

Disable a static source explicitly before removing its entry or reverting the
binary. Removal alone leaves the historical source row unchanged. Older binaries
reject the new fields; do not silently drop the adapter and interpret the page as
a feed. Previously accepted evidence, chunk coordinates and immutable jobs remain
readable. No schema migration, grant widening or private-tree permission repair is
part of this increment.

Actual websites, public-PKI/DNS interoperability, source-specific licensing,
representative volume and long-running deployment remain separate acceptance.
JavaScript rendering, crawling, automatic charset detection, restricted content,
other formats and broader workflow scheduling remain in the full backlog.
