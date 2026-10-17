"""Native product admission after a completed retired-record purge."""

import pytest

from osint_workbench import intelligence
from osint_workbench.contracts import DocumentInput
from osint_workbench.errors import WorkbenchError
from tests.test_record_purge import apply as purge
from tests.test_record_purge import change
from tests.test_record_purge import context as context
from tests.test_recovery import _input

pytestmark = pytest.mark.integration


def test_briefing_refuses_document_purged_after_preflight(context, monkeypatch):
    writer, store = context["writer"], context["store"]
    document = writer.ingest(_input(), b"synthetic raw", store)
    original = writer.document
    removed = []

    def validated_then_purged(identifier, *args, **kwargs):
        result = original(identifier, *args, **kwargs)
        change(context, document, "retire")
        removed.append(purge(context, document))
        return result

    # The preflight returns genuine visible evidence, then the real lifecycle and
    # SQL purge commit before the product transaction acquires shared authority.
    monkeypatch.setattr(writer, "document", validated_then_purged)
    with pytest.raises(WorkbenchError, match="DOCUMENT_RETIRED_OR_EXPIRED"):
        intelligence.create_briefing(writer, [document])
    assert len(removed) == 1
    with context["admin"].connect() as conn:
        assert not conn.execute(
            "SELECT 1 FROM ow.documents WHERE document_id=%s", (document,)
        ).fetchone()
        assert not conn.execute("SELECT 1 FROM ow.briefings").fetchone()
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM ow.lifecycle_events WHERE action='purge'"
            ).fetchone()["n"]
            == 1
        )


def test_briefing_keeps_visible_historical_document_selection(context):
    writer, store = context["writer"], context["store"]
    first = writer.ingest(_input(), b"synthetic first raw", store)
    source = _input()
    replacement = DocumentInput(
        source_id=source.source_id,
        external_id=source.external_id,
        title="Later version",
        text="Later synthetic evidence.",
    )
    second = writer.ingest(replacement, b"synthetic later raw", store)
    assert first != second
    result = intelligence.create_briefing(writer, [first])
    assert result["selected_documents"] == [first]
    assert result["degraded"] is True
    with context["admin"].connect() as conn:
        assert (
            conn.execute("SELECT document_id FROM ow.document_heads").fetchone()["document_id"]
            == second
        )
        assert conn.execute(
            "SELECT 1 FROM ow.briefings WHERE briefing_id=%s", (result["briefing_id"],)
        ).fetchone()
