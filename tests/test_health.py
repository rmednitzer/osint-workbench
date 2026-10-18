"""Threshold decisions are offline; SQL semantics use a separate native reader case."""

import copy
import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from osint_workbench.database import SCHEMA_VERSION
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.health import check
from osint_workbench.service import ReadService

LIMITS = {
    "max_source_age_seconds": 300,
    "max_pending_jobs": 2,
    "max_failed_jobs": 0,
}


def fixture(*, status=None, sources=None):
    counts = {
        "sources": 2,
        "enabled_sources": 1,
        "unobserved_sources": 0,
        "stale_sources": 0,
        "error_sources": 0,
        "future_source_successes": 0,
    }
    counts.update(sources or {})
    value = {
        "schema_version": SCHEMA_VERSION,
        "ready_jobs": 1,
        "running_jobs": 1,
        "failed_jobs": 0,
        "retrieval": "lexical",
        "synthetic_private_field": "private-host.invalid /private/canary",
    }
    value.update(status or {})
    calls = []

    def execute(query, parameters):
        calls.append((query, parameters))
        return SimpleNamespace(fetchone=lambda: counts)

    service = SimpleNamespace(
        status=lambda: copy.deepcopy(value),
        db=SimpleNamespace(connect=lambda: nullcontext(SimpleNamespace(execute=execute))),
    )
    return service, calls


def test_explicit_threshold_equality_and_fixed_safe_facts():
    service, calls = fixture()
    result = check(service, **LIMITS)
    assert result["ready"] and result["reasons"] == []
    assert result["thresholds"] == {**LIMITS, "require_retrieval": False}
    assert result["facts"]["pending_jobs"] == 2
    assert result["facts"]["retrieval_state"] == "not_configured"
    assert "private" not in json.dumps(result)
    assert len(calls) == 1 and calls[0][1] == (300,)
    assert "FROM ow.source_status" in calls[0][0]


@pytest.mark.parametrize(
    "status,sources,options,reason",
    [
        ({"schema_version": SCHEMA_VERSION - 1}, {}, {}, "HEALTH_SCHEMA_MISMATCH"),
        ({}, {"sources": 0, "enabled_sources": 0}, {}, "HEALTH_UNCONFIGURED"),
        ({}, {"enabled_sources": 0}, {}, "HEALTH_UNCONFIGURED"),
        ({}, {"unobserved_sources": 1}, {}, "HEALTH_SOURCE_UNOBSERVED"),
        ({}, {"stale_sources": 1}, {}, "HEALTH_SOURCE_STALE"),
        ({}, {"error_sources": 1}, {}, "HEALTH_SOURCE_ERROR"),
        ({}, {"future_source_successes": 1}, {}, "HEALTH_SOURCE_CLOCK_SKEW"),
        ({"running_jobs": 2}, {}, {}, "HEALTH_PENDING_JOBS_EXCEEDED"),
        ({"failed_jobs": 1}, {}, {}, "HEALTH_FAILED_JOBS_EXCEEDED"),
        ({}, {}, {"require_retrieval": True}, "HEALTH_RETRIEVAL_UNAVAILABLE"),
        (
            {"retrieval": "hybrid-exact", "retrieval_state": "migration_required"},
            {},
            {"require_retrieval": True},
            "HEALTH_RETRIEVAL_UNAVAILABLE",
        ),
    ],
)
def test_unconfigured_and_degraded_states_fail_explicitly(status, sources, options, reason):
    service, _ = fixture(status=status, sources=sources)
    result = check(service, **{**LIMITS, **options})
    assert not result["ready"] and result["reasons"] == [reason]


def test_required_retrieval_checks_only_compatible_generation_metadata():
    service, _ = fixture(
        status={
            "retrieval": "hybrid-exact",
            "retrieval_state": "ready",
            "generation_id": "private-generation-canary",
        }
    )
    assert check(service, **LIMITS, require_retrieval=True)["ready"]
    assert "canary" not in json.dumps(check(service, **LIMITS, require_retrieval=True))


@pytest.mark.parametrize(
    "status,sources",
    [
        ({"schema_version": True}, {}),
        ({"ready_jobs": -1}, {}),
        ({"running_jobs": "0"}, {}),
        ({"failed_jobs": 0.0}, {}),
        ({"retrieval": "private-canary"}, {}),
        ({"retrieval": "hybrid-exact", "retrieval_state": "private-canary"}, {}),
        ({}, {"sources": True}),
        ({}, {"enabled_sources": 3}),
        ({}, {"stale_sources": 2}),
    ],
)
def test_malformed_status_never_reports_ready_or_echoes_backend_values(status, sources):
    service, _ = fixture(status=status, sources=sources)
    result = check(service, **LIMITS)
    assert not result["ready"] and result["reasons"] == ["HEALTH_INVALID_STATUS"]
    assert "canary" not in json.dumps(result)


@pytest.mark.parametrize("value", [None, [], "private-health-canary", {}])
@pytest.mark.parametrize("phase", ["status", "sources"])
def test_missing_or_non_object_status_is_a_fixed_failure(value, phase):
    service, _ = fixture()
    if phase == "status":
        service.status = lambda: value
    else:
        service.db.connect = lambda: nullcontext(
            SimpleNamespace(execute=lambda *args: SimpleNamespace(fetchone=lambda: value))
        )
    result = check(service, **LIMITS)
    assert not result["ready"] and result["reasons"] == ["HEALTH_INVALID_STATUS"]
    assert "canary" not in json.dumps(result)


@pytest.mark.parametrize(
    "changes",
    [
        {"max_source_age_seconds": 0},
        {"max_source_age_seconds": -1},
        {"max_source_age_seconds": 31536001},
        {"max_source_age_seconds": True},
        {"max_pending_jobs": -1},
        {"max_pending_jobs": 1000001},
        {"max_pending_jobs": 0.0},
        {"max_failed_jobs": -1},
        {"max_failed_jobs": False},
        {"require_retrieval": 1},
    ],
)
def test_threshold_configuration_fails_before_any_backend_access(changes):
    with pytest.raises(WorkbenchError, match="^INVALID_HEALTH_THRESHOLDS$"):
        check(None, **{**LIMITS, **changes})


@pytest.mark.parametrize("phase", ["status", "sources"])
def test_unavailable_backend_errors_are_fixed_and_private(phase):
    service, _ = fixture()

    def fail(*args):
        raise RuntimeError("private-host.invalid /private/canary")

    if phase == "status":
        service.status = fail
    else:
        service.db.connect = fail
    result = check(service, **LIMITS)
    assert not result["ready"] and result["reasons"] == ["HEALTH_UNAVAILABLE"]
    assert "private" not in json.dumps(result)


@pytest.mark.integration
def test_native_reader_aggregates_disabled_sources_freshness_and_job_thresholds(
    databases, tmp_path
):
    writer, reader, _ = databases
    service = ReadService(
        reader, EvidenceStore(tmp_path / "absent-read-only-store", read_only=True)
    )
    assert check(service, **LIMITS)["reasons"] == ["HEALTH_UNCONFIGURED"]
    with writer.connect() as conn:
        conn.execute("""INSERT INTO ow.sources(source_id,enabled,last_success,freshness_seconds)
            VALUES ('synthetic-fresh',true,clock_timestamp()-interval '10 seconds',60),
              ('synthetic-disabled',false,NULL,60)""")
    result = check(service, **LIMITS)
    assert result["ready"] and result["facts"]["sources"] == 2
    assert result["facts"]["enabled_sources"] == 1
    writer.enqueue("synthetic-health", "synthetic-health", {})
    result = check(service, **{**LIMITS, "max_pending_jobs": 0})
    assert result["reasons"] == ["HEALTH_PENDING_JOBS_EXCEEDED"]
    with writer.connect() as conn:
        conn.execute("UPDATE ow.jobs SET status='failed'")
        conn.execute("""UPDATE ow.sources SET last_success=clock_timestamp()-interval '2 minutes',
            last_error='private-health-canary' WHERE enabled""")
    result = check(service, **LIMITS)
    assert result["reasons"] == [
        "HEALTH_SOURCE_ERROR",
        "HEALTH_FAILED_JOBS_EXCEEDED",
    ]
    assert "canary" not in json.dumps(result)
    with writer.connect() as conn:
        conn.execute("UPDATE ow.sources SET last_error=NULL WHERE enabled")
    # Once not masked by an error, the source view's 60-second stale state
    # also applies when the explicit max is 300.
    assert "HEALTH_SOURCE_STALE" in check(service, **LIMITS)["reasons"]
    with writer.connect() as conn:
        conn.execute("""UPDATE ow.sources SET last_success=clock_timestamp()-interval '6 minutes',
            freshness_seconds=86400,last_error=NULL WHERE enabled""")
    assert "HEALTH_SOURCE_STALE" in check(service, **LIMITS)["reasons"]
    with writer.connect() as conn:
        conn.execute("UPDATE ow.sources SET enabled=false")
    assert check(service, **{**LIMITS, "max_failed_jobs": 1})["reasons"] == ["HEALTH_UNCONFIGURED"]
