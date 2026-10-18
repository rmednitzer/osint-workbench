"""Bounded KEV format mapping; no endpoint, crawling or applicability inference."""

import json
import re
from datetime import date

from pydantic import TypeAdapter

from .advisory import UtcDatetime
from .contracts import DocumentInput

_TIMESTAMP = TypeAdapter(UtcDatetime)
_REQUIRED = {
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
}
_OPTIONAL = {"knownRansomwareCampaignUse", "forensicTriage", "notes", "cwes"}


def _text(value, maximum=100000, *, empty=False):
    if type(value) is not str or not int(not empty) <= len(value) <= maximum or "\x00" in value:
        raise ValueError("invalid KEV string")
    value.encode("utf-8")
    return value


def _date(value):
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", _text(value, 10)):
        raise ValueError("invalid KEV date")
    date.fromisoformat(value)


def parse_catalogue(page, source_id, limit):
    """All-or-nothing format admission; upstream extensions require explicit review."""
    required = {"catalogVersion", "dateReleased", "count", "vulnerabilities"}
    if type(page) is not dict or not required <= page.keys() or page.keys() - required - {"title"}:
        raise ValueError("invalid KEV envelope")
    _text(page["catalogVersion"], 128)
    _TIMESTAMP.validate_json(json.dumps(page["dateReleased"]), strict=True)
    if "title" in page:
        _text(page["title"], 2000)
    items = page["vulnerabilities"]
    if (
        type(items) is not list
        or len(items) > limit
        or type(page["count"]) is not int
        or page["count"] != len(items)
    ):
        raise ValueError("invalid KEV count")
    documents = []
    identities = set()
    for item in items:
        if (
            type(item) is not dict
            or not _REQUIRED <= item.keys()
            or item.keys() - _REQUIRED - _OPTIONAL
        ):
            raise ValueError("invalid KEV record")
        identity = _text(item["cveID"], 28)
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", identity) or identity in identities:
            raise ValueError("invalid KEV identity")
        identities.add(identity)
        for name in _REQUIRED - {"cveID", "dateAdded", "dueDate"}:
            _text(item[name], 1900 if name == "vulnerabilityName" else 100000)
        _date(item["dateAdded"])
        _date(item["dueDate"])
        for name, choices in (
            ("knownRansomwareCampaignUse", ("Known", "Unknown")),
            ("forensicTriage", ("Yes", "No")),
        ):
            if name in item and item[name] not in choices:
                raise ValueError("invalid KEV enum")
        if "notes" in item:
            _text(item["notes"], empty=True)
        if "cwes" in item:
            cwes = item["cwes"]
            if type(cwes) is not list or len(cwes) > 100:
                raise ValueError("invalid KEV weaknesses")
            for cwe in cwes:
                if not re.fullmatch(r"CWE-[0-9]+", _text(cwe, 64)):
                    raise ValueError("invalid KEV weakness")
        # Catalogue timestamps stay in the linked raw object, not in every record's
        # text identity. Date-only fields never become invented publication instants.
        documents.append(
            DocumentInput(
                source_id=source_id,
                external_id=identity,
                title=f"{identity}: {item['vulnerabilityName']}",
                text=json.dumps(
                    item, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False
                ),
                published_at=None,
            )
        )
    return documents
