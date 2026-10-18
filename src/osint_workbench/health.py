"""Explicit operator thresholds over reader-visible aggregate metadata.

This is a bounded readiness sample, not an SLO, evidence-integrity probe or model
execution test. Source age uses the database clock and also respects each source's
configured freshness state. Retrieval readiness means the configured index reports
an active compatible generation; it does not prove corpus currency or recall.
Status and source aggregates use separate read transactions and are not an atomic
snapshot. Existing database connection, statement and admission timeouts apply.
"""

from .database import SCHEMA_VERSION
from .errors import WorkbenchError
from .service import ReadService

_SOURCE_COUNTS = (
    "sources",
    "enabled_sources",
    "unobserved_sources",
    "stale_sources",
    "error_sources",
    "future_source_successes",
)
_SOURCE_QUERY = """SELECT count(*) AS sources,
    count(*) FILTER (WHERE enabled) AS enabled_sources,
    count(*) FILTER (WHERE enabled AND last_success IS NULL) AS unobserved_sources,
    count(*) FILTER (WHERE enabled AND (freshness='stale' OR
      extract(epoch FROM statement_timestamp()-last_success)>%s)) AS stale_sources,
    count(*) FILTER (WHERE enabled AND last_error IS NOT NULL) AS error_sources,
    count(*) FILTER (WHERE enabled AND last_success>statement_timestamp())
      AS future_source_successes
    FROM ow.source_status"""


def _count(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def check(
    service: ReadService,
    *,
    max_source_age_seconds: int,
    max_pending_jobs: int,
    max_failed_jobs: int,
    require_retrieval: bool = False,
) -> dict:
    """Return fixed aggregate facts and reason codes, excluding arbitrary backend fields.

    Pending means ready plus running jobs of every kind. Disabled sources do not
    fail freshness checks, but an installation without enabled sources is not
    ready. Equality with a job/age limit is accepted. Configuration bounds constrain
    inputs only; callers supply every numeric threshold explicitly.
    """
    if (
        type(max_source_age_seconds) is not int
        or not 1 <= max_source_age_seconds <= 31536000
        or type(max_pending_jobs) is not int
        or not 0 <= max_pending_jobs <= 1000000
        or type(max_failed_jobs) is not int
        or not 0 <= max_failed_jobs <= 1000000
        or type(require_retrieval) is not bool
    ):
        raise WorkbenchError("INVALID_HEALTH_THRESHOLDS")
    result = {
        "format": 1,
        "kind": "aggregate_health",
        "ready": False,
        "reasons": [],
        "thresholds": {
            "max_source_age_seconds": max_source_age_seconds,
            "max_pending_jobs": max_pending_jobs,
            "max_failed_jobs": max_failed_jobs,
            "require_retrieval": require_retrieval,
        },
        "facts": {
            "schema_version": None,
            **dict.fromkeys(_SOURCE_COUNTS),
            "pending_jobs": None,
            "failed_jobs": None,
            "retrieval": "unavailable",
            "retrieval_state": "unavailable",
        },
    }
    try:
        status = service.status()
        if not isinstance(status, dict) or not all(
            _count(status.get(key))
            for key in ("schema_version", "ready_jobs", "running_jobs", "failed_jobs")
        ):
            result["reasons"] = ["HEALTH_INVALID_STATUS"]
            return result
        retrieval = status.get("retrieval")
        retrieval_state = status.get("retrieval_state", "not_configured")
        if retrieval not in ("lexical", "hybrid-exact") or (
            retrieval == "hybrid-exact"
            and retrieval_state
            not in ("ready", "unconfigured", "migration_required", "incompatible")
        ):
            result["reasons"] = ["HEALTH_INVALID_STATUS"]
            return result
        with service.db.connect() as conn:
            # Aggregate in SQL: source IDs, URLs, timestamps and error text never
            # enter the result or Python-side source inventory.
            sources = conn.execute(_SOURCE_QUERY, (max_source_age_seconds,)).fetchone()
        if not isinstance(sources, dict) or not all(_count(sources.get(k)) for k in _SOURCE_COUNTS):
            result["reasons"] = ["HEALTH_INVALID_STATUS"]
            return result
        if any(sources[k] > sources["enabled_sources"] for k in _SOURCE_COUNTS[2:]) or (
            sources["enabled_sources"] > sources["sources"]
        ):
            result["reasons"] = ["HEALTH_INVALID_STATUS"]
            return result
        facts = result["facts"]
        facts.update({key: sources[key] for key in _SOURCE_COUNTS})
        facts.update(
            schema_version=status["schema_version"],
            pending_jobs=status["ready_jobs"] + status["running_jobs"],
            failed_jobs=status["failed_jobs"],
            retrieval=retrieval,
            retrieval_state=retrieval_state if retrieval == "hybrid-exact" else "not_configured",
        )
        reasons = result["reasons"]
        for failed, code in (
            (facts["schema_version"] != SCHEMA_VERSION, "HEALTH_SCHEMA_MISMATCH"),
            (facts["enabled_sources"] == 0, "HEALTH_UNCONFIGURED"),
            (facts["unobserved_sources"] > 0, "HEALTH_SOURCE_UNOBSERVED"),
            (facts["stale_sources"] > 0, "HEALTH_SOURCE_STALE"),
            (facts["error_sources"] > 0, "HEALTH_SOURCE_ERROR"),
            (facts["future_source_successes"] > 0, "HEALTH_SOURCE_CLOCK_SKEW"),
            (facts["pending_jobs"] > max_pending_jobs, "HEALTH_PENDING_JOBS_EXCEEDED"),
            (facts["failed_jobs"] > max_failed_jobs, "HEALTH_FAILED_JOBS_EXCEEDED"),
            (
                require_retrieval and (retrieval != "hybrid-exact" or retrieval_state != "ready"),
                "HEALTH_RETRIEVAL_UNAVAILABLE",
            ),
        ):
            if failed:
                reasons.append(code)
        result["ready"] = not reasons
    except Exception:
        # Backend error codes and exception strings can carry operator data;
        # none are an allowed public health reason or fact.
        result["reasons"] = ["HEALTH_UNAVAILABLE"]
    return result
