# Security and support scope

This is experimental integration software. It has no production security or
availability guarantee. Check STATUS.md and revision-specific CI evidence.

Do not expose the stdio reader through an unauthenticated HTTP wrapper, use an
administrator DSN for runtime readers, or give model/parser processes host-control
credentials. Keep source configuration, state, evidence and secrets out of Git.
Retrieved text is hostile data; normalization does not eliminate prompt injection.

Use GitHub's private vulnerability reporting feature if available. Otherwise avoid
posting exploit details, credentials, personal data or private infrastructure in a
public issue; first request a private reporting route without disclosing the flaw.
No response-time commitment or continuously staffed security team is claimed.

Dependencies, model code, role grants, HTTP destinations, publication artifacts and
recovery behaviour require continued review. Scanner success alone is not assurance.
