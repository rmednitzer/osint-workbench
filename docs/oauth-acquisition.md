# Bounded OAuth client-credentials acquisition

This optional API authentication mode obtains one short-lived bearer token for
one due collection tick. It adds no provider endpoint, subscription, inference
route or new MCP authority. Existing [rights and unmetered declarations](api-acquisition.md)
still apply. OAuth authentication does not establish downstream content rights.

## Private configuration

Set `auth.kind` to `oauth-client-credentials`, retain a non-`public` authentication
context and use the existing `credential` reference for the **client secret**.
The `oauth` object supplies the privately configured token endpoint, client ID
and explicit nonempty scopes. For example, using a deliberately inert endpoint:

```json
{
  "kind": "oauth-client-credentials",
  "context": "synthetic-account-v1",
  "credential": {"kind": "systemd", "name": "provider-token"},
  "oauth": {
    "token_endpoint": "https://auth.example.invalid/token",
    "client_id": "synthetic-client",
    "scopes": ["records:read"]
  }
}
```

This replaces the `auth` member of an otherwise unchanged private `ApiSource`.
The existing opt-in credential drop-in can deliver `provider-token`; file custody
and systemd UID-private ACL checks remain unchanged. Never put the secret itself
in JSON, argv or an environment variable. Keep client identifiers, scopes and both
endpoints outside Git. The collector shares its existing account trust boundary;
this is not per-provider process or restricted-rights isolation.

The token endpoint must be HTTPS with no user information, query or fragment.
Literal non-public addresses are refused at configuration; resolved addresses
are validated and pinned at dispatch, including rejection of mixed public/private
answers. Neither endpoint may redirect. Client IDs are 1–256 printable non-space
ASCII characters. There must be 1–32 unique scope tokens, each at most 128
characters in the OAuth scope-token character set. Grant type, authentication
method and request parameter names are fixed; arbitrary audiences/resources,
headers, discovery, dynamic registration and provider extensions are unsupported.

## Runtime contract

Disabled, busy, not-due and exhausted-cycle sources make no token request. After
reserving the normal source attempt, the collector resolves the client secret
once and sends a bounded form POST using `client_secret_basic`. Each Basic
component is form-encoded before Base64 encoding. The client secret goes only
to the explicit token endpoint; the resource receives only the issued bearer.
Both requests retain public-address pinning, TLS verification, bounded framing,
no redirects/proxies/cookies and the original tick deadline.

Token responses are at most 16384 bytes with strict UTF-8 JSON, duplicate-key and
nesting checks. Require `access_token` (1–4096 characters in bearer-token syntax),
case-insensitive bearer `token_type`, and integer `expires_in` from 1 to 86400
seconds. This deliberately requires expiry even though the base specification
does not make it mandatory. If returned, `scope` must match exactly the requested
set. Omitted scope has the protocol's unchanged-scope meaning; this is not an
independent verification of the server's actual grants. Unknown response
parameters, including refresh/ID tokens, remain inert and are discarded.

Expiry starts conservatively before the token request. Resource transport uses
the earlier of declared expiry and the existing tick deadline. Remote validity
and actual audience enforcement remain the authorization/resource servers'
responsibility; the client treats tokens as opaque and trusts no JWT claims.
No token response is placed in CAS, SQL, cursor state, parser input or diagnostics.
The issued bearer is not cached between ticks. Python objects do not promise
memory zeroization or protection from the same UID/root.

The isolated evidence parser still receives only the resource response and its
stripped environment. Exact raw and JSON-decoded occurrences of either the
client secret or issued token reject resource admission before storage. This is
a backstop, not arbitrary encoded-secret or sensitive-content detection.

## Failure, rotation and compatibility

Token rejection, invalid/expired grants, scope changes, redirects and transport
failures use fixed sanitized errors. Token-endpoint 429/503 carries the existing
validated Retry-After into source backoff. Resource rejection does not trigger
reauthentication or replay. There is one grant POST and at most one resource GET
per tick, no internal retry, refresh loop, fallback authentication or ambiguous
grant replay. A later due tick may obtain a new grant; request billing must still
be explicitly declared unmetered.

A missing or unsafe secret stops before HTTP. Replacing a systemd source secret
requires reactivation; provider revocation is separate. Changing OAuth endpoint,
client ID, scopes, references or context changes the private acquisition profile
and resets continuation/freshness. Existing none/bearer/API-key serialization
omits the absent OAuth member, preserving old profile hashes and cursors.
No migration or SQL privilege change is needed.

Stop the timer/service and reconcile its control group before rollback. Disable
the source or restore its previous compatible authentication configuration;
older binaries reject the new mode. Keep accepted schema-11 data/history and a
matching private checkpoint. Revoke credentials/tokens at the provider if needed.

## Engineering baseline and acceptance

The protocol baseline was reviewed on 2026-10-18 against
[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), sections 2.3.1, 3.3,
4.4 and 5.1, [bearer syntax](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1)
and [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5).
Current security guidance recommends asymmetric client authentication; this
bounded compatibility mode implements symmetric Basic only. mTLS, private-key
JWT and sender-constrained tokens need separate implementation and evidence.
This is not a claim of complete OAuth security-profile conformance.

`tests/test_oauth.py` uses actual TLS with distinct synthetic authorization and
resource origins. Native acquisition tests reconcile SQL/CAS and denial,
reflection, backoff, no-dispatch and legacy identity behavior. The guarded
two-LTS service fixture additionally uses real loaded-secret delivery, grant and
resource requests, refusal/backoff/recovery and downstream readers. The [two-LTS service receipt](testing/oauth-service-2026-10-19.json) binds
passing execution to its named source, wheel and harness/unit hashes. The
[CodeQL review](testing/oauth-codeql-triage-2026-10-19.md) records two individual
fixture dispositions without query/path exclusions. No actual
provider or Janes contract, entitlement, content rights or target-host deployment
is established. See [ADR-0049](adr/0049-oauth-client-credentials.md).
