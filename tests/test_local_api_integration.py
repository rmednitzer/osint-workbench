"""Installed API-to-native generation and API-to-database acceptance paths."""

import json

import httpcore
import pytest

from osint_workbench import intelligence as intel
from osint_workbench.local_api import LocalApiGenerator
from tests.test_generation import SCHEMA
from tests.test_generation import native_generator as native_generator
from tests.test_intelligence import claim, setup
from tests.test_local_api import OPERATION, api_peer, completion, manifest

pytestmark = pytest.mark.integration


def test_real_native_chat_api_over_loopback(native_generator):
    """A fixture-only bridge preserves the native server's actual HTTP API bytes.

    This qualifies the pinned native chat wire path, not Ollama/vLLM deployment.
    """

    def forward(method, path, body):
        assert path in {"/v1/models", "/v1/chat/completions"}
        with httpcore.ConnectionPool(uds=native_generator.manifest.socket_path) as pool:
            result = pool.request(
                method,
                "http://inference.invalid" + path,
                headers={"Content-Type": "application/json"},
                content=body or b"",
            )
            return result.status, result.content

    with api_peer(forward=forward) as (url, calls):
        generator = LocalApiGenerator(manifest(url, timeout_seconds=15, max_output_tokens=256))
        result = generator.generate("Return a JSON result.", SCHEMA, operation=OPERATION)
        assert result["output"] == {"answer": "verified"}
        assert sum(c["method"] == "POST" for c in calls) == 1


@pytest.mark.parametrize(
    ("claims", "expected"),
    [([claim()], "proposed"), ([claim("Invented evidence")], "failed"), ([], "abstained")],
)
def test_api_proposals_pass_actual_sql_evidence_and_review_boundary(
    databases, tmp_path, monkeypatch, claims, expected
):
    writer, reader, _, store, document = setup(databases, tmp_path)
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(tmp_path / "admission.lock"))
    result = completion(
        choices=[
            {
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps({"claims": claims})},
            }
        ]
    )
    with api_peer(result=result) as (url, calls):
        generator = LocalApiGenerator(manifest(url))
        job = intel.enqueue(writer, generator, document, data_class="public")
        assert intel.enqueue(writer, generator, document, data_class="public") == job
        outcome = intel.enrich_once(writer, store, generator)
        assert outcome["status"] == expected
        assert intel.enrich_once(writer, store, generator)["status"] == "idle"
        assert sum(c["method"] == "POST" for c in calls) == 1
    rows = intel.assertions(reader)["results"]
    if expected == "proposed":
        assert len(rows) == 1 and rows[0]["review_state"] == "pending"
        assert rows[0]["quote"] == claim()["quote"]
        assert intel.create_briefing(writer, [document])["degraded"]
    else:
        assert rows == []


def test_api_ambiguous_job_is_terminal_and_never_replayed(databases, tmp_path, monkeypatch):
    writer, reader, _, store, document = setup(databases, tmp_path)
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(tmp_path / "admission.lock"))
    with api_peer(disconnect=True) as (url, calls):
        generator = LocalApiGenerator(manifest(url))
        intel.enqueue(writer, generator, document, data_class="public")
        outcome = intel.enrich_once(writer, store, generator)
        assert outcome == {"status": "failed", "error": "INFERENCE_OUTCOME_UNKNOWN"}
        assert intel.enrich_once(writer, store, generator)["status"] == "idle"
        state = intel.enqueue(writer, generator, document, data_class="public", describe=True)
        assert state["job_status"] == "failed"
        assert state["enqueue_effect"] == "terminal_preserved" and state["requeued"] is False
        assert intel.enrich_once(writer, store, generator)["status"] == "idle"
        assert sum(c["method"] == "POST" for c in calls) == 1
    assert intel.assertions(reader)["results"] == []


@pytest.mark.parametrize("terminal", ["succeeded", "failed", "cancelled"])
def test_enqueue_reports_atomic_terminal_preservation_without_reset(databases, terminal):
    from osint_workbench.jobs import Jobs

    writer, _, _ = databases
    state = writer.enqueue_state("fixture.enqueue", "fixed", {})
    assert state["job_status"] == "ready" and state["enqueue_effect"] == "pending_or_running"
    jobs = Jobs(writer)
    row = jobs.claim(kinds=["fixture.enqueue"])
    running = writer.enqueue_state("fixture.enqueue", "fixed", {})
    assert running["job_status"] == "running" and running["job_id"] == state["job_id"]
    if terminal == "succeeded":
        jobs.finish(row["job_id"], row["fence"], {})
    elif terminal == "failed":
        jobs.fail(row["job_id"], row["fence"], "FIXTURE_FAILURE", retryable=False)
    else:
        jobs.cancel(row["job_id"])
    before = jobs.inspect(row["job_id"])
    stored = writer.enqueue_state("fixture.enqueue", "fixed", {})
    assert stored == {
        "job_id": state["job_id"],
        "job_status": terminal,
        "enqueue_effect": "terminal_preserved",
        "requeued": False,
    }
    after = jobs.inspect(row["job_id"])
    assert after["status"] == terminal and after["attempt"] == before["attempt"]
    assert after["events"] == before["events"]
    assert writer.enqueue("fixture.enqueue", "fixed", {}) == state["job_id"]
