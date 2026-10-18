# Security and support scope

This is experimental integration software. It has no production security or
availability guarantee. Check STATUS.md and revision-specific CI evidence.

Do not expose the stdio reader through an unauthenticated HTTP wrapper, use an
administrator DSN for runtime readers, or give model/parser processes host-control
credentials. Keep source configuration, state, evidence and secrets out of Git.
Retrieved text is hostile data; normalization does not eliminate prompt injection.

MCP's seven tools read through a scoped reader identity. Optional configured
local embeddings/reranking do not grant database write authority. The MCP client
can disclose returned content to its own model provider; read-only access is not
an egress control. Governed remote inference is a separate operator-selected
[cloud route](docs/cloud-routes.md), with independent spending and settlement
authority. Do not treat an installed adapter or an operator's declared provider
facts as an independently verified sovereignty approval.

Private vulnerability reporting is enabled in the observed
[repository settings](docs/testing/repository-settings.json). Use the repository
Security tab's private reporting route. If that route is unavailable, avoid
posting exploit details, credentials, personal data or private infrastructure in a
public issue; first request a private reporting route without disclosing the flaw.
No response-time commitment or continuously staffed security team is claimed.

Dependencies, model code, role grants, HTTP destinations, publication artifacts and
recovery behaviour require continued review. Scanner success alone is not assurance.
