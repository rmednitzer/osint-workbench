"""Read projection semantics, without treating quotation location as entailment."""

import hashlib
import json
from contextlib import contextmanager
from copy import deepcopy

import pytest

from osint_workbench.intelligence import assertions


class ReadFixture:
    def __init__(self, rows):
        self.rows = rows
        self.parameters = None

    @contextmanager
    def connect(self):
        yield self

    def execute(self, query, parameters):
        assert "ow.current_assertions" in query
        self.parameters = parameters
        return self

    def fetchall(self):
        return deepcopy(self.rows)


def proposal():
    return {
        "assertion_id": "a" * 64,
        "document_id": "b" * 64,
        "subject": "availability",
        "predicate": "affects",
        "object": "availability",
        "statement": "Storage is unavailable.",
        "polarity": "asserted",
        "start_offset": 17,
        "end_offset": 40,
        "quote": "Storage is unavailable.",
        "review_state": "pending",
    }


def test_absent_labels_are_explicit_bindings_with_stable_v1_hash_inputs():
    original = proposal()
    assert original["subject"] not in original["quote"]
    db = ReadFixture([original])
    result = assertions(db, document_id="b" * 64, subject="availability", limit=3, offset=2)
    assert result["ontology_version"] == "assertion-proposals/2"
    assert result["entity_resolution"] == "not-performed"
    row = result["results"][0]
    assert db.parameters == ("b" * 64, "b" * 64, "availability", "availability", 3, 2)
    for role in ("subject", "object"):
        expected = hashlib.sha256(
            json.dumps(["b" * 64, 17, 40, role, "availability"]).encode()
        ).hexdigest()
        assert row[role + "_label_binding_id"] == expected
        assert role + "_mention_id" not in row
    assert row["subject_label_binding_id"] != row["object_label_binding_id"]
    assert {key: row[key] for key in original} == original
    assert db.rows == [original]  # Projection never rewrites stored data.


@pytest.mark.parametrize(
    ("field", "value"),
    [("document_id", "c" * 64), ("start_offset", 18), ("end_offset", 41), ("subject", "Storage")],
)
def test_label_binding_is_scoped_to_document_span_role_and_label(field, value):
    first = proposal()
    changed = {**first, field: value}
    a, b = assertions(ReadFixture([first, changed]))["results"]
    assert a["subject_label_binding_id"] != b["subject_label_binding_id"]
    if field == "subject":
        assert a["object_label_binding_id"] == b["object_label_binding_id"]


def test_binding_is_not_an_assertion_identity_or_review_authority():
    first = proposal()
    changed = {**first, "assertion_id": "d" * 64, "review_state": "accept"}
    a, b = assertions(ReadFixture([first, changed]))["results"]
    assert a["assertion_id"] != b["assertion_id"]
    assert a["review_state"] != b["review_state"]
    for role in ("subject", "object"):
        assert a[role + "_label_binding_id"] == b[role + "_label_binding_id"]


def test_empty_assertion_page_retains_explicit_v2_semantics():
    assert assertions(ReadFixture([])) == {
        "ontology_version": "assertion-proposals/2",
        "entity_resolution": "not-performed",
        "results": [],
    }
