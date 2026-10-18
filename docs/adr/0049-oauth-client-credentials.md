# ADR-0049: Bound OAuth client credentials to one acquisition tick

Status: Accepted

## Context and decision criteria

Static bearer/API-key references cannot obtain expiring machine-to-machine
credentials. Adding OAuth must preserve private configuration, least privilege,
bounded public HTTPS dispatch, no credential retention, honest source progress
and no automatic retry of ambiguous work. It must not imply a commercial
provider contract or relax existing rights/billing restrictions.

## Alternatives

| Option | Consequences |
| --- | --- |
| No change | Operator must independently provision static access tokens; no new protocol authority |
| Generic OAuth SDK and discovery | More flows, implicit caching/retry, discovery and extension behavior than this profile needs |
| mTLS/private-key JWT first | Preferred asymmetric direction, but adds key/certificate custody, signing and provider-specific registration/rotation acceptance |
| Bounded explicit client-secret Basic flow | Reuses checked secret references and collector authority with one configured grant and one resource request |
| Persistent token/refresh cache | Adds sensitive durable state and recovery/concurrency requirements; unnecessary for one-page ticks |

## Decision

Add `oauth-client-credentials` to `ApiAuth` with one nested explicit `OAuthClient`
configuration and reuse `credential` for the client secret. The token endpoint,
client ID and explicit scopes remain private. No dynamic discovery or provider
extras. Share the existing bounded JSON HTTP exchange so transport hardening
does not diverge between grant and data requests. Existing GET failure semantics
remain unchanged; OAuth maps token-stage errors to fixed codes and preserves
typed Retry-After without logging response text.

Resolve the secret only after source admission and before any grant dispatch.
Authenticate the grant using individually form-encoded Basic components. Admit
only bounded bearer grants with explicit expiry and unchanged declared scope.
Discard extension values and never persist the grant response or send it into
the evidence parser. Use conservative monotonic expiry from before issuance and
cap resource transport by the existing tick deadline. No cache, refresh token,
JWT-claim trust, fallback or retry after resource rejection.

Check both client-secret and bearer reflection before resource storage. This
does not establish arbitrary encoded-secret detection, memory zeroization or
same-UID isolation. Tokens go only to the configured resource; actual scope and
audience enforcement remain server responsibilities. Basic is a bounded
compatibility option, not implementation of the recommended asymmetric methods
or complete OAuth security conformance. The [operator contract](../oauth-acquisition.md)
records the primary protocol/security baseline and exact acceptance limits.

Preserve old authentication serialization by omitting absent OAuth metadata.
Old source profile identities and continuation therefore remain stable. New
OAuth configuration changes reset continuation through the existing private
profile hash; token values never enter that hash. No dependency, schema, SQL
privilege, MCP or inference change is required. Restricted rights and metered
queries remain refused; authentication is not downstream-use permission.

## Verification, impact and rollback

Installed native TLS tests use distinct synthetic authorization/resource hosts
and inspect exact encoded client auth, scopes and bearer separation. Negative
cases cover malformed/oversized grants, unsupported token types, expiry, scope
changes, duplicate keys, TLS failures, redirects and fixed errors. Native SQL/CAS
tests establish no grant retention, both-secret reflection refusal, denial without
reauthentication, Retry-After and zero dispatch when disabled/not due/cycle-capped.
The guarded two-LTS service fixture establishes loaded-secret grant/resource
exchange, denial/backoff/recovery and reader postconditions at a named artifact.
Earlier receipts do not float to this revision. U1/U4/U8/U10/U12 apply; full
provider, rights-domain and source acceptance scenarios remain open.

Blast radius is the opt-in API authentication path and its shared HTTP helper;
existing feed transport and seven MCP reads remain unchanged. Stop the API
timer/service, verify its control group has settled, then disable or deliberately
restore compatible private authentication before reverting binaries. Accepted
schema-11 evidence remains readable; there is no reverse migration. Preserve a
matching checkpoint and revoke provider credentials separately if required.
