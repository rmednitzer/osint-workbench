"""Malformed private envelopes fail with bounded domain diagnostics."""

import copy
import uuid

import pytest

from osint_workbench import lifecycle, recovery
from osint_workbench.errors import WorkbenchError


@pytest.mark.parametrize("mutation", ["control", "tables", "item", "row"])
def test_malformed_policy_has_domain_error(mutation):
    policy = {
        "format": 1,
        "kind": "lifecycle_policy",
        "control": {"singleton": True, "dataset_id": str(uuid.uuid4()), "revision": 0},
        "tables": {name: [] for name in lifecycle.POLICY_TABLES},
    }
    assert lifecycle.validate_policy(copy.deepcopy(policy)) == policy
    if mutation == "control":
        policy["control"]["dataset_id"] = "synthetic-private-diagnostic-canary"
    elif mutation == "tables":
        policy["tables"] = None
    elif mutation == "row":
        policy["tables"]["lifecycle_items"] = [None]
    else:
        policy["tables"]["lifecycle_items"] = [
            {
                "source_id": "fixture",
                "external_key": "a" * 64,
                "retention_class": "not an identifier",
                "retain_until": None,
            }
        ]
    with pytest.raises(WorkbenchError, match="^INVALID_LIFECYCLE_POLICY$") as caught:
        lifecycle.validate_policy(policy)
    assert "canary" not in repr(caught.value)


@pytest.mark.parametrize("tables", [None, {}, {"snapshots": [None]}, {"snapshots": []}])
def test_malformed_recovery_provenance_has_domain_error(tables):
    with pytest.raises(WorkbenchError, match="^INVALID_RECOVERY_BUNDLE$"):
        recovery._provenance(tables, {})
