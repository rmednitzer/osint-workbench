# Design references

These are design inputs, not claims of certification or completed implementation.
Stable S identifiers used in the assurance/profile documents resolve here. S5/S6
are not allocated. Verify exact contracts, licences and applicability when
implementing a profile; a documentation URL is not an execution receipt.

## Reading decision history

An ADR records a decision and its original acceptance boundary; its date, schema
numbers, pending work and test counts are not automatically current operational
instructions. Dated successor notes connect bounded implemented slices to the
original proposed full profiles without promoting the whole programme to
accepted. Follow [STATUS](../STATUS.md), the current runbooks and source-bound
receipts for current behaviour and execution evidence. Later green checks do not
clear historical failures or publication findings, and older receipts are not
relabelled as current ones.

## S1

Leveson and Thomas, STPA Handbook (2018):
[handbook](https://psas.scripts.mit.edu/home/get_file.php?name=STPA_handbook.pdf).

## S2

NIST SSDF SP 800-218 v1.1:
[final publication](https://csrc.nist.gov/pubs/sp/800/218/final).

## S3

OWASP ASVS: [project and versioned releases](https://github.com/OWASP/ASVS).
The selected technical checklist is 5.0.0; the initial bounded selection uses the
[versioned English source](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json).
[Control evidence](security/control-evidence.md) records scope and gaps. Complete
applicability and level assessment remain open; referencing the standard or
passing selected tests is not conformance.

## S4

MCP [security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).
The SDK is locked in uv.lock; [ADR-0039](adr/0039-mcp-v2-dependency-refresh.md)
records the implemented stdio SDK v2 boundary. This security reference also covers
remote authorization, which remains a target profile; citing it does not establish
an implemented OAuth/resource-server flow.

## S7

pgvector [upstream documentation](https://github.com/pgvector/pgvector).
Exact retrieval is the current oracle; filtered ANN acceptance remains open.

## S8

llama.cpp [server documentation at the tested native-source revision](https://github.com/ggml-org/llama.cpp/blob/620d2225cc436ab0b001e3200e590e3b286ef9ab/tools/server/README.md).
The preparation script also verifies the source archive digest. This is not a
claim of compatibility with arbitrary future server versions. The
[preparation script](../scripts/prepare_native.py) and
[ADR-0039](adr/0039-mcp-v2-dependency-refresh.md) identify the current selected
stable fixture source. Earlier receipts retain their earlier native revisions
and must not inherit the current source identity.

## S9

OWASP [prompt injection guidance](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
Bounded authority and validated effects remain necessary for local and remote models.
