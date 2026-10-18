## Change and reason

Describe the trigger, resulting behavior and affected contracts. Link the relevant
ADR/requirement for a material design or authority change.

## Verification

Record actual commands/results, tested revision/artifact identity and any missing
native, provider, hardware or semantic evidence. Explain dependency/lock/build
constraint changes and relevant failure, permission or recovery checks.
For MCP changes, distinguish modern and legacy protocol results and verify that
the seven-tool read boundary and sanitized errors remain intact.

## Impact and recovery

Describe migration compatibility, deployment impact and rollback where applicable.
Confirm public files/artifacts contain synthetic examples and no private source
catalogs, configuration, identifiers or operational logs.
Keep agent session/conversation links out of this description and Git metadata.
Preflight the exact planned merge message with the publication scanner's
`--message-file` option before merging; use an explicit reviewed subject/body.
