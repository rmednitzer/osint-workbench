import json
import sys

import pytest

from osint_workbench import cli


@pytest.mark.parametrize("failed", [0, 1])
def test_worker_cli_aggregate_exit_and_read_only_store(monkeypatch, capsys, failed):
    monkeypatch.setattr(sys, "argv", ["osint-workbench", "work", "--max-jobs", "7"])
    monkeypatch.setenv("OW_CHUNK_DSN", "synthetic")
    monkeypatch.setenv("OW_EVIDENCE_ROOT", "/synthetic")

    class WorkerDatabase(str):
        def validate_worker(self, capability):
            assert capability == "ow_chunk_worker"

    monkeypatch.setattr(cli, "Database", WorkerDatabase)

    def store(path, *, read_only):
        assert str(path) == "/synthetic" and read_only
        return "read-only-store"

    monkeypatch.setattr(cli, "EvidenceStore", store)
    report = {"kind": "chunk_worker_tick", "failed": failed}

    def run(db, evidence, *, max_jobs):
        assert db == "synthetic" and evidence == "read-only-store" and max_jobs == 7
        return report

    monkeypatch.setattr(cli, "run_batch", run)
    if failed:
        with pytest.raises(SystemExit) as error:
            cli.main()
        assert error.value.code == 1
    else:
        cli.main()
    captured = capsys.readouterr()
    assert json.loads(captured.out) == report and not captured.err


@pytest.mark.parametrize("limit", [0, 1001])
def test_worker_limit_refused_before_backend(monkeypatch, capsys, limit):
    monkeypatch.setattr(sys, "argv", ["ow", "work", "--max-jobs", str(limit)])
    monkeypatch.delenv("OW_CHUNK_DSN", raising=False)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1
    assert json.loads(capsys.readouterr().err) == {"error": "INVALID_WORK_LIMIT"}


@pytest.mark.parametrize("group", ["-1", "4294967295", "a", "١", ""])
def test_invalid_explicit_evidence_group_never_creates_store(monkeypatch, group):
    monkeypatch.setenv("OW_EVIDENCE_READ_GID", group)
    with pytest.raises(cli.WorkbenchError, match="INVALID_EVIDENCE_GROUP"):
        cli._writable_store()


@pytest.mark.parametrize("ready", [True, False])
def test_health_cli_requires_operator_thresholds_and_propagates_readiness(
    monkeypatch, capsys, ready
):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ow",
            "health",
            "--max-source-age-seconds",
            "456",
            "--max-pending-jobs",
            "12",
            "--max-failed-jobs",
            "0",
            "--require-retrieval",
        ],
    )
    monkeypatch.setenv("OW_READER_DSN", "synthetic")
    monkeypatch.setenv("OW_EVIDENCE_ROOT", "/synthetic")
    monkeypatch.delenv("OW_ENCODER_MANIFEST", raising=False)
    monkeypatch.delenv("OW_RERANKER_MANIFEST", raising=False)
    monkeypatch.setattr(cli, "Database", lambda _: "db")
    monkeypatch.setattr(cli, "EvidenceStore", lambda *_, **__: "read-store")
    monkeypatch.setattr(cli, "ReadService", lambda *_, **__: "reader-service")

    def check(service, **thresholds):
        assert service == "reader-service"
        assert thresholds == {
            "max_source_age_seconds": 456,
            "max_pending_jobs": 12,
            "max_failed_jobs": 0,
            "require_retrieval": True,
        }
        return {"ready": ready, "reasons": [] if ready else ["HEALTH_UNAVAILABLE"]}

    monkeypatch.setattr(cli.health, "check", check)
    if ready:
        cli.main()
    else:
        with pytest.raises(SystemExit) as error:
            cli.main()
        assert error.value.code == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["ready"] == ready and not captured.err


def test_health_cli_has_no_implicit_thresholds(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["ow", "health"])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert not capsys.readouterr().out
