# Bounded authenticated API acquisition

Acquisition supports the explicit `bounded-json-pages/1` contract and the
[`cisa-kev/1` catalogue mapping](kev-acquisition.md), not a generic provider SDK
or a Janes integration. Core schema **11**, optional retrieval profile **4**
and checkpoint format **2** apply. Run the packaged migration before acquisition.
There are no bundled endpoints, credentials or enabled sources. An opt-in
[single-source service/timer](deployment.md#scheduled-api-profile) is available.
No operational deployment or provider subscription is implied.

## Admission and authority

An operator supplies one private `ApiSource` JSON object outside Git. The endpoint
must use HTTPS, contain no configured query string or credentials, and pass the
existing public-destination validation. The worker pins validated addresses while
preserving TLS identity. Data acquisition makes GET requests and refuses every redirect. The optional
[OAuth client-credentials mode](oauth-acquisition.md) makes one explicit bounded
token POST before the resource GET; it cannot select a provider search POST.
The provider cannot select another destination through its response: the only
continuation is a bounded opaque value encoded into the configured endpoint's
`cursor` query parameter. Cookies, arbitrary authentication headers and SDK retry
behaviour are outside this profile.

The operator must explicitly declare `rights: all-existing-uses-permitted` and
`request_billing: unmetered`. These are attestations, not independently established
licence clearance or billing guarantees. Narrower or unknown rights and metered
requests fail configuration validation. Existing readers, retrieval, enrichment,
cloud release policies and exports cannot enforce per-source licence isolation.
Do not ingest licensed material whose permitted uses are narrower than this
instance's existing consumers. Separate rights-domain instances/storage remain a
future design, not an implemented restriction on downstream use.

Use distinct source IDs for unrelated collections. A source ID shares the existing
feed/API schedule, acquisition exclusion lock and history. Changing the profile
invalidates continuation, validators and freshness; it does not delete old data.
Do not use feed and API commands concurrently as competing configurations for one
source ID.

## Configuration and command

The following endpoint is deliberately non-operational. Replace it only in private
operator configuration with an authorized contract-compatible endpoint.

```json
{
  "source_id": "synthetic-api",
  "endpoint": "https://api.example.invalid/records",
  "enabled": false,
  "adapter": "bounded-json-pages/1",
  "rights": "all-existing-uses-permitted",
  "request_billing": "unmetered",
  "auth": {
    "kind": "bearer",
    "context": "provider-account-v1",
    "credential": {"kind": "systemd", "name": "provider-token"}
  },
  "poll_seconds": 900,
  "freshness_seconds": 86400
}
```

`auth.kind` supports `none`, `bearer`, `api-key` and
[`oauth-client-credentials`](oauth-acquisition.md). Authentication requires a
credential reference and a non-`public` context identifier. The context identifies
the operator's authentication scope/version; it is not a secret. API keys support
only the fixed `X-API-Key` or `apiKey` header names. Arbitrary destinations, header
names, query credentials, other OAuth flows and interactive sign-in are unsupported.
OAuth additionally requires the private `auth.oauth` object; existing static modes
refuse that object and omit it from serialization, preserving their profile hashes.

With privately configured `OW_COLLECTOR_DSN` and `OW_EVIDENCE_ROOT`, run:

```sh
osint-workbench collect-api --config private/api-source.json --max-pages 1 --timeout-seconds 60
```

This is one due-aware tick for one source. The page cap is exactly 1; values other than 1 are rejected. The
network/parser/admission deadline is greater than zero and at most 120 s,
default 60 s. Remaining time is checked between documents and before page acceptance,
with SQL statement/lock timeouts. Filesystem durability, database finalization and
failure recording can extend total wall time; this is not a hard process deadline. `--restart` explicitly discards the current private continuation/history, clears
freshness and makes the source due before beginning a new cycle. It preserves
accepted historical documents and may refetch already observed records. Use it
only after reconciling an expired cursor, cycle limit or changed upstream contract;
it does not establish that the abandoned cycle was complete. Without `--restart`,
the durable schedule and continuation remain authoritative. `poll_seconds` is
60–86400, independently of `freshness_seconds` (60–31536000). Disabled and
not-due configurations dispatch no request. The optional API timer is separately
provisioned; the RSS timer does not automatically discover API configurations.

## Bounded JSON page contract

For `bounded-json-pages/1`, the response must be HTTP 200 with `application/json` and identity/no content
encoding. Compressed responses are rejected. Each body is at most 10 MiB. The
UTF-8 JSON object contains exactly `items` and `next_cursor`:

```json
{
  "items": [
    {"id": "record-1", "title": "Synthetic report", "text": "Synthetic evidence."}
  ],
  "next_cursor": null
}
```

Each item contains exactly `id`, `title`, `text` and optionally `published_at`.
IDs are nonempty and at most 1024 characters, titles at most 2000 and text at most
1000000; timestamps use the parser's UTC datetime contract. A page has at most
1000 items and no duplicate IDs. Unknown fields, duplicate JSON keys, nonfinite
numbers, invalid UTF-8/surrogates, invalid timestamps and nesting beyond 32 levels
reject the entire page. `next_cursor` is null or at most 1024 printable ASCII
characters. An empty items list is valid and does not imply deletion.

The parser runs in a subprocess with an environment stripped of caller secrets,
CPU/address-space/output/file-descriptor limits, an eight-second-or-remaining
wall timeout and a 16 MiB output bound. This is resource containment, not a
filesystem/network sandbox against a compromised process with the same UID.

## Progress, failure and recovery

Each invocation admits at most one page and retains that response digest on its
own durable run, including empty pages and pages reusing existing document heads.
Validated page documents, run counts and continuation state commit together after
the referenced immutable objects are durable. A crash before commit can leave
unreferenced objects; existing reviewed orphan GC applies. Earlier committed
pages remain accepted if a later page fails. Logical retirement and expiry still
suppress acceptance. Changed content uses existing immutable version/current-head
semantics; a page window is not a complete snapshot and absence is not withdrawal.

A tick with another cursor returns `partial`; its run records status `failed`
with `API_PARTIAL`, and the source is not marked newly successful. This uses the
existing run-state vocabulary while preserving the distinct CLI partial outcome.
Normal polling schedules the next page; partial progress is not an automatic
in-process retry. Only an accepted
terminal page updates `last_success`. Private SQL state holds the current cursor,
canonical configuration hash, page count and SHA-256 history of continuation
values. A repeated continuation across ticks fails `API_CURSOR_LOOP`; a cycle is
limited to 128 pages. Terminal acceptance resets page/cursor history for the next
poll. The profile hash includes references/context and policy declarations, never
the resolved credential value. Rotate authentication context when the logical
provider account or authorization scope changes.

Failures retain committed progress and fixed diagnostic codes. Authentication,
entitlement, redirect, media/schema, size, cursor and transport failures remain
explicit. HTTP 429/503 may extend the reserved due time using bounded validated
`Retry-After`; otherwise existing exponential per-source backoff applies. There
is no sleep/retry loop, provider-wide quota, charging ledger, watermark or deletion
reconciliation. A source stuck at the cycle cap requires operator reconciliation and an explicit
`--restart` if a new cycle is intended; no implicit reset skips the unresolved cycle.

Checkpoints are private and include this state. Restore clears every API cursor,
profile hash, page counter and cursor history, disables sources and requires
operator reconciliation before collection. Exact published core 4–10 pairs retain
explicit adoption rules. Core 11 is not backward compatible with older binaries;
retain the matching database/evidence checkpoint when rolling back.

## Credential custody

A reference selects a systemd credential name or an absolute file path. Values
are never read from a token environment variable. Systemd resolution uses the
trusted service-provided `CREDENTIALS_DIRECTORY`; file references use the same
checked descriptor walk. A guarded disposable-runner fixture tests real systemd
delivery and cross-unit isolation on both supported LTS releases; its execution
receipt is required separately from local unit tests. The optional API service
uses the same delivery contract; provision and test the selected host delivery
independently before adoption.

The resolver refuses symlink components, writable/untrusted ancestors, nonregular
files, multiple hard links, unsafe owner/mode and files changing during the read.
The exact root-owned sticky `/tmp` ancestor is a fixture-compatible exception.
The file channel requires root or service-UID ownership and mode 0400 or 0600.
The systemd channel additionally accepts root-owned mode 0440 only when the
opened file's Linux POSIX access ACL grants read permission to exactly the current
service UID, with no group or other access. This mode represents the ACL mask,
not permission granted to the owning group; see the [systemd delivery implementation](https://github.com/systemd/systemd/blob/v255/src/core/exec-credential.c). Missing, malformed or broader ACLs
fail closed. The checked ACL does not authenticate a genuine systemd mount.
The same UID-private ACL requirement applies in shared-evidence deployments;
sharing an evidence group never grants access to a credential through this check.

All token values contain 1–4096 printable non-space ASCII bytes without a trailing
newline. Never put token values in CLI arguments or public manifests; fixtures
use authored/generated synthetic values only.

A credential is resolved for the tick without fallback; failure is reported using
fixed codes. The parser receives no authentication credential channel or inherited service
environment. Exact active-token occurrences in raw bytes and all decoded JSON
strings and keys are rejected before storage as `API_CREDENTIAL_REFLECTED`. This is a
backstop: arbitrary encodings, unknown secrets, sensitive provider content and
compromise of the credentialed worker are not covered. Python secret objects do
not promise zeroization. Same-UID processes and privileged administrators remain outside this custody
boundary.

For rotation, provision the replacement through the selected credential backend,
revoke the old value at the provider, and verify both success and denial paths.
Systemd snapshots loaded credentials at activation: replacing its source file
does not refresh an already running service. Coordinate reactivation and provider
revocation explicitly. Replacing a file alone does not revoke an already disclosed token. Do not assume
host-encrypted credentials remain decryptable after machine replacement; preserve
an independently controlled reprovisioning procedure.

## Evidence and remaining gates

`tests/test_api_parser.py`, `tests/test_credentials.py`,
`tests/test_api_acquisition.py`, collector-role tests and recovery tests exercise
synthetic contracts. Installed native transport/database and both LTS service
credential-delivery evidence must be bound to the candidate artifact before
operational claims. The [scheduled API service receipt](testing/scheduled-api-hardening-2026-10-18.json)
records the passing disconnected two-LTS service path at its named revision. A
parser, unit or synthetic service pass does not establish actual provider operation.

Provider schemas beyond the bounded KEV mapping, other pagination, documented search POSTs, OAuth beyond client credentials, mTLS,
signed requests, compressed documents, HTML/JSON-LD, JavaScript rendering,
webhooks/streaming, paid queries, source qualification, rights-domain enforcement,
query-disclosure policy and broader real-provider acceptance remain outstanding.
