import time
from datetime import datetime

import pytest
from pydantic import ValidationError

from osint_workbench.collection import feed_documents
from osint_workbench.contracts import DocumentInput, SourceConfig
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.fetch import public_addresses, resolve, validate_url
from osint_workbench.retrieval import EmbeddingSpace, reciprocal_rank_fusion
from osint_workbench.text import chunks, evidence_span, html_text


def test_config_empty_and_strict():
    assert SourceConfig.model_validate_json('{"sources":[]}').sources == []
    with pytest.raises(ValidationError):
        SourceConfig.model_validate_json('{"sources":[],"run_shell":true}')
    with pytest.raises(ValidationError):
        SourceConfig.model_validate_json(
            '{"sources":[{"source_id":"x","url":"a"},{"source_id":"x","url":"b"}]}'
        )


def test_reject_naive_timestamp():
    with pytest.raises(ValidationError):
        DocumentInput(
            source_id="fixture",
            external_id="one",
            title="One",
            text="Text",
            published_at=datetime(2026, 1, 1),
        )


@pytest.mark.parametrize(
    ("text", "quote", "literal"),
    [
        ("Straße ABC", "abc", "ABC"),
        ("Die Straße endet.", "STRASSE", "Straße"),
        ("Alpha\n beta", "alpha beta", "Alpha\n beta"),
        ("İstanbul", "i\u0307stanbul", "İstanbul"),
    ],
)
def test_coordinate_preserving_evidence(text, quote, literal):
    start, end, actual = evidence_span(text, quote)
    assert text[start:end] == actual == literal


def test_evidence_rejects_partial_expansion_and_fabrication():
    for quote in ["s", "invented"]:
        with pytest.raises(WorkbenchError):
            evidence_span("ß", quote)


def test_html_is_text_not_an_injection_guarantee():
    value = html_text(
        "<p>Visible instructions remain data.</p><script>execute()</script><p>End</p>"
    )
    assert "Visible instructions" in value and "execute()" not in value and "End" in value


def test_chunks_cover_original_and_are_not_token_claims():
    text = "x" * 103
    parts = chunks(text, size=40, overlap=5)
    assert parts[-1]["end"] == len(text)
    assert all(text[p["start"] : p["end"]] == p["text"] for p in parts)
    assert parts[0]["chunker"] == "characters/1"


def test_immutable_evidence_and_tampering(tmp_path):
    store = EvidenceStore(tmp_path / "objects")
    sha = store.put(b"fixture evidence")
    assert store.put(b"fixture evidence") == sha
    assert store.get(sha) == b"fixture evidence"
    (tmp_path / "objects" / sha[:2] / sha).write_bytes(b"altered")
    with pytest.raises(WorkbenchError, match="INTEGRITY"):
        store.get(sha)
    with pytest.raises(WorkbenchError, match="INTEGRITY"):
        store.put(b"fixture evidence")


def test_readonly_and_symlink_boundary(tmp_path):
    root = tmp_path / "objects"
    store = EvidenceStore(root)
    sha = store.put(b"a")
    reader = EvidenceStore(root, read_only=True)
    with pytest.raises(WorkbenchError, match="READ_ONLY"):
        reader.put(b"b")
    target = root / sha[:2] / sha
    target.unlink()
    secret = tmp_path / "outside"
    secret.write_bytes(b"a")
    target.symlink_to(secret)
    with pytest.raises(WorkbenchError, match="UNAVAILABLE"):
        reader.get(sha)
    with pytest.raises(WorkbenchError, match="INVALID_DIGEST"):
        reader.get("../outside")


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
        "192.0.2.1",
    ],
)
def test_prohibited_addresses(address):
    with pytest.raises(WorkbenchError, match="BLOCKED"):
        public_addresses([address])


def test_entire_dns_answer_validated():
    with pytest.raises(WorkbenchError, match="BLOCKED"):
        public_addresses(["8.8.8.8", "127.0.0.1"])


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://user:pass@example.invalid",
        "https://example.invalid:22/",
        "https://example.invalid/#fragment",
        "https://example.invalid/\nheader",
    ],
)
def test_bad_urls(url):
    with pytest.raises(WorkbenchError):
        validate_url(url)


def test_real_resolver_rejects_loopback():
    with pytest.raises(WorkbenchError, match="BLOCKED"):
        resolve("127.0.0.1", 80, time.monotonic() + 5)


def test_embedding_identity_and_numeric_validation():
    space = EmbeddingSpace(
        model_revision="fixture-model-rev",
        tokenizer_revision="fixture-tokenizer-rev",
        query_template="query: {}",
        document_template="passage: {}",
        pooling="mean",
        dimensions=2,
        normalized=True,
        metric="cosine",
        precision="float32",
    )
    space.validate_vector([1.0, 0.0])
    assert space.fingerprint() != space.model_copy(update={"query_template": "{}"}).fingerprint()
    for vector in [[1.0], [float("nan"), 0.0], [0.0, 0.0], [True, 0.0]]:
        with pytest.raises(WorkbenchError):
            space.validate_vector(vector)


def test_fusion_has_explicit_ranks_and_stable_ties():
    result = reciprocal_rank_fusion([["a", "b"], ["b", "a"]])
    assert [r["id"] for r in result] == ["a", "b"]
    assert result[0]["rrf_score"] == pytest.approx(1 / 61 + 1 / 62)
    with pytest.raises(WorkbenchError):
        reciprocal_rank_fusion([["a", "a"]])


def test_feed_parser_preserves_evidence_and_rejects_unknown_format():
    raw = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Synthetic</title>
    <link>https://example.invalid/</link><description>Fixture</description><item>
    <guid>fixture-1</guid><title>Storage update</title>
    <description>Persistent evidence.</description>
    <pubDate>Sat, 17 Oct 2026 08:00:00 GMT</pubDate></item></channel></rss>"""
    docs = feed_documents(raw, "fixture")
    assert len(docs) == 1 and docs[0].text == "Persistent evidence."
    assert docs[0].published_at.utcoffset().total_seconds() == 0
    with pytest.raises(WorkbenchError, match="PARSE"):
        feed_documents(b"<html>Not a feed</html>", "fixture")


def test_disposable_parser_rejects_bad_items_and_entities():
    missing_body = b"""<rss version="2.0"><channel><item><guid>one</guid>
    <title>No evidence</title></item></channel></rss>"""
    with pytest.raises(WorkbenchError, match="FEED_INVALID_ENTRY"):
        feed_documents(missing_body, "fixture")
    hostile = b"""<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY leak SYSTEM
    "file:///nonexistent-synthetic-evidence">]><rss version="2.0"><channel>
    <item><guid>one</guid><title>Untrusted</title><description>&leak;</description>
    </item></channel></rss>"""
    with pytest.raises(WorkbenchError):
        feed_documents(hostile, "fixture")
