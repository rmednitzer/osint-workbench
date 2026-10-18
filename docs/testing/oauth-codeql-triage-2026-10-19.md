# OAuth fixture CodeQL dispositions, 2026-10-19

Python SARIF `1977079617` at
`c6debc5fc0cac6d69e757f15828ecb2de2e6b315` reported alerts 47 and 48,
`py/weak-sensitive-data-hashing`, in `scripts/reference_network.py`. The complete
SARIF thread flows, source definitions, callers and fixture authority were
reviewed individually. Neither path implements operational password storage.

## Alert 47: published synthetic bearer

The reported source is the public `OAUTH_ACCESS_TOKEN` fixture constant; the sink
is its SHA-256 resource-peer comparison at line 336. That value authorizes only
authored records inside the explicitly guarded disconnected namespace. It is
not a private credential or human password. Hashing it does not claim secrecy
or password-hardening; constant-time comparison retains the fixture's expected
request distinction. Its presence in public test code is intentional.

Disposition: false positive for password hashing, recorded on the individual
alert. Reassess if the constant becomes confidential, protects operational
resources or leaves the bounded synthetic peer.

## Alert 48: generated client-auth verifier

The reported source is `_api_token` at line 460, through the Basic encoding
assembled at lines 459–461, to SHA-256 at line 462. Call-site inspection finds
one credentialed `ReferenceNetwork` invocation, in the guarded service harness.
It generates the secret with `secrets.token_urlsafe(32)`; the other invocation
is the unauthenticated feed fixture. Acquired content, MCP inputs and operator
passwords do not select this verifier. Encoding the fixed client ID and random
secret does not reduce the secret's 256-bit generation entropy.

Disposition: false positive for low-entropy password hashing, recorded on the
individual alert. SHA-256 is a random-token verifier with constant-time comparison,
not a password database. The separately protected loaded-secret source remains
a credential file and is not claimed encrypted at rest. Reassess if generation,
callers, entropy or fixture authority changes, especially human-selected secrets.

The earlier [random-verifier review](codeql-triage-2026-10-18.md#scheduled-api-fixture-successor)
records the primary OWASP/CodeQL distinction. Runtime OAuth sends credentials
through checked custody and TLS; it adds no password-hashing service. No query
family, path, security setting or gate is excluded by these individual
dispositions. Static review does not establish service acceptance, rights or
actual provider compatibility; those require separate revision-bound evidence.
