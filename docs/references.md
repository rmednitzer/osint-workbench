# Design references

These are design inputs, not claims of certification or completed implementation.
Stable S identifiers used in the assurance/profile documents resolve here. S5/S6
are not allocated. Verify exact contracts, licences and applicability when
implementing a profile; a documentation URL is not an execution receipt.

## S1

Leveson and Thomas, STPA Handbook (2018):
[handbook](https://psas.scripts.mit.edu/home/get_file.php?name=STPA_handbook.pdf).

## S2

NIST SSDF SP 800-218 v1.1:
[final publication](https://csrc.nist.gov/pubs/sp/800/218/final).

## S3

OWASP ASVS: [project and versioned releases](https://owasp.org/projects/asvs).
The selected technical checklist is 5.0.0; applicable controls and evidence remain
to be selected explicitly. Referencing the project is not conformance.

## S4

MCP [security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).
The SDK is locked in uv.lock; remote authorization remains a target profile.

## S7

pgvector [upstream documentation](https://github.com/pgvector/pgvector).
Exact retrieval is the current oracle; filtered ANN acceptance remains open.

## S8

llama.cpp [server documentation at the tested native-source revision](https://github.com/ggml-org/llama.cpp/blob/f2f667b02dc76d675395ae3b14546c8108d26387/tools/server/README.md).
The preparation script also verifies the source archive digest. This is not a
claim of compatibility with arbitrary future server versions.

## S9

OWASP [prompt injection guidance](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
Bounded authority and validated effects remain necessary for local and remote models.
