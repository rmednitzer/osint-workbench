"""Authored KEV-format fixtures; no actual catalogue entries or source endpoint."""

import copy
import json
import time

import pytest

from osint_workbench.api_acquisition import _documents, _page
from osint_workbench.api_parser import parse
from osint_workbench.errors import WorkbenchError
from tests.test_api_transport import source

RECORD = {
    "cveID": "CVE-2099-10001",
    "vendorProject": "Synthetic vendor",
    "product": "Synthetic product",
    "vulnerabilityName": "Synthetic issue",
    "dateAdded": "2026-10-18",
    "shortDescription": "Authored evidence; <script>data only</script>.",
    "requiredAction": "Synthetic source recommendation, not an operator command.",
    "dueDate": "2026-11-01",
    "knownRansomwareCampaignUse": "Unknown",
    "forensicTriage": "No",
    "notes": "https://reference.example.invalid/advisory",
    "cwes": ["CWE-99999"],
}


def catalogue(items=None, **changes):
    items = [copy.deepcopy(RECORD)] if items is None else items
    return {
        "title": "Synthetic catalogue",
        "catalogVersion": "synthetic-1",
        "dateReleased": "2026-10-18T12:00:00.000Z",
        "count": len(items),
        "vulnerabilities": items,
    } | changes


def raw(page=None):
    return json.dumps(catalogue() if page is None else page).encode()


def test_explicit_adapter_preserves_all_assertions_and_date_precision():
    documents, cursor = parse(raw(), "kev-fixture", "cisa-kev/1")
    assert cursor is None and len(documents) == 1
    document = documents[0]
    assert document.external_id == RECORD["cveID"]
    assert document.source_id == "kev-fixture"
    assert document.title == "CVE-2099-10001: Synthetic issue"
    assert json.loads(document.text) == RECORD
    assert document.published_at is None
    # Envelope release changes cannot re-version every otherwise unchanged entry.
    newer = catalogue(catalogVersion="synthetic-2", dateReleased="2026-10-19T12:00:00Z")
    assert parse(raw(newer), "kev-fixture", "cisa-kev/1")[0] == documents


def test_optional_fields_are_absent_not_invented_and_empty_catalogue_is_explicit():
    item = {
        k: v
        for k, v in RECORD.items()
        if k not in {"notes", "knownRansomwareCampaignUse", "forensicTriage", "cwes"}
    }
    doc = parse(raw(catalogue([item])), "kev-fixture", "cisa-kev/1")[0][0]
    assert json.loads(doc.text) == item
    assert parse(raw(catalogue([])), "kev-fixture", "cisa-kev/1") == ([], None)
    item.update(notes="", cwes=[])
    assert json.loads(parse(raw(catalogue([item])), "kev-fixture", "cisa-kev/1")[0][0].text) == item


@pytest.mark.parametrize(
    "name,value",
    [
        ("cveID", "CVE-2099-123"),
        ("cveID", "cve-2099-10001"),
        ("cveID", "CVE-2099-" + "1" * 20),
        ("cveID", 1),
        ("dateAdded", "2026-02-30"),
        ("dateAdded", "20261018"),
        ("dueDate", "2026-11-01T00:00:00Z"),
        ("dueDate", None),
        ("shortDescription", ""),
        ("shortDescription", "\udfff"),
        ("product", "x" * 100001),
        ("vendorProject", False),
        ("vulnerabilityName", "x" * 1901),
        ("vulnerabilityName", "null\x00name"),
        ("knownRansomwareCampaignUse", "No"),
        ("knownRansomwareCampaignUse", None),
        ("forensicTriage", "Unknown"),
        ("forensicTriage", True),
        ("notes", []),
        ("cwes", "CWE-1"),
        ("cwes", ["CWE-X"]),
        ("cwes", ["CWE-1"] * 101),
        ("cwes", ["CWE-" + "1" * 61]),
        ("unreviewedField", "private-canary"),
    ],
)
def test_bad_record_rejects_whole_catalogue_with_fixed_error(name, value):
    item = dict(RECORD, cveID="CVE-2099-10002")
    item[name] = value
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        parse(raw(catalogue([RECORD, item])), "kev-fixture", "cisa-kev/1")


@pytest.mark.parametrize(
    "changes",
    [
        {"count": True},
        {"count": -1},
        {"count": 2},
        {"count": 1.0},
        {"vulnerabilities": {}},
        {"catalogVersion": ""},
        {"catalogVersion": 1},
        {"dateReleased": "2026-10-18"},
        {"dateReleased": "2026-10-18T12:00:00"},
        {"title": None},
        {"unreviewedField": "private-canary"},
    ],
)
def test_schema_drift_and_count_mismatch_fail_closed(changes):
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        parse(raw(catalogue(**changes)), "kev-fixture", "cisa-kev/1")


def test_missing_required_fields_duplicate_keys_and_identities_are_rejected():
    for name in (
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
    ):
        item = dict(RECORD)
        del item[name]
        with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
            parse(raw(catalogue([item])), "kev-fixture", "cisa-kev/1")
    for page in (catalogue([RECORD, RECORD]), catalogue() | {"count": 0}):
        with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
            parse(raw(page), "kev-fixture", "cisa-kev/1")
    for data in (b'{"count":0,' + raw()[1:], raw().replace(b'"cveID":', b'"cveID":"x","cveID":')):
        with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
            parse(data, "kev-fixture", "cisa-kev/1")


def test_adapter_selection_is_explicit_and_not_content_sniffed():
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        parse(raw(), "kev-fixture")
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        parse(raw(), "kev-fixture", "unreviewed/1")
    with pytest.raises(WorkbenchError, match="^API_PARSE_FAILED$"):
        _documents(raw(catalogue(count=0)), "kev-fixture", time.monotonic() + 8, "cisa-kev/1")
    with pytest.raises(WorkbenchError, match="^API_CURSOR_INVALID$"):
        _page(source(adapter="cisa-kev/1"), "unexpected", "", time.monotonic() + 8)


def test_installed_subprocess_accepts_catalogue_above_generic_page_cap_and_enforces_own_cap():
    items = [dict(RECORD, cveID=f"CVE-2099-{10000 + n}") for n in range(1001)]
    documents, cursor = _documents(
        raw(catalogue(items)), "kev-fixture", time.monotonic() + 8, "cisa-kev/1"
    )
    assert len(documents) == 1001 and cursor is None
    assert json.loads(documents[-1].text) == items[-1]
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        parse(raw(catalogue([RECORD] * 10001)), "kev-fixture", "cisa-kev/1")
