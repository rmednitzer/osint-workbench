import copy
import importlib.util
import socket
from pathlib import Path

import pytest


@pytest.fixture
def sbom(monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location("check_sbom", scripts / "check_sbom.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inputs():
    raw = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {
            "component": {
                "name": "osint-workbench",
                "version": "1.0",
                "bom-ref": "root-component",
                "author": "private",
            }
        },
        "components": [
            {
                "name": "example",
                "version": "2.0",
                "bom-ref": "example==2.0",
                "description": "/private/operator-file",
                "externalReferences": [{"type": "website", "url": "private"}],
                "licenses": [{"license": {"id": "MIT", "text": {"content": "private"}}}],
            }
        ],
        "dependencies": [
            {"ref": "root-component", "dependsOn": ["example==2.0"]},
            {"ref": "example==2.0", "dependsOn": []},
        ],
    }
    receipt = {
        "source": {"commit": "a" * 40, "tree": "b" * 40},
        "runtime": {"python": "3.14.8", "implementation": "CPython", "os": "ubuntu-26.04"},
        "workflow": {"run_id": "123", "run_attempt": "1"},
        "inventory": {
            "distributions": [
                {"name": "osint-workbench", "version": "1.0"},
                {"name": "example", "version": "2.0"},
            ]
        },
    }
    return raw, receipt


def test_projection_validates_offline_preserves_edges_and_removes_private_fields(sbom, monkeypatch):
    def refuse_network(*args, **kwargs):
        raise AssertionError("schema validation must not resolve network resources")

    monkeypatch.setattr(socket, "create_connection", refuse_network)
    monkeypatch.setattr(socket, "socket", refuse_network)
    raw, receipt = inputs()
    result = sbom.project(raw, receipt)
    assert "private" not in sbom.encoded(result).decode()
    assert result["components"][0]["licenses"] == [
        {"license": {"id": "MIT", "acknowledgement": "declared"}}
    ]
    assert {item["ref"]: item["dependsOn"] for item in result["dependencies"]} == {
        "urn:osint-workbench:application:1.0": ["pkg:pypi/example@2.0"],
        "pkg:pypi/example@2.0": [],
    }
    assert result["compositions"][0]["aggregate"] == "incomplete"


def test_schema_rejects_invalid_version_and_unknown_properties(sbom):
    raw, receipt = inputs()
    result = sbom.project(raw, receipt)
    with pytest.raises(sbom.EvidenceError, match="SCHEMA_INVALID"):
        sbom.schema_validate(dict(result, version="invalid"))
    with pytest.raises(sbom.EvidenceError, match="SCHEMA_INVALID"):
        sbom.schema_validate(dict(result, unexpected="not allowed"))


def test_inventory_mismatch_and_dangling_edges_fail_closed(sbom):
    raw, receipt = inputs()
    receipt["inventory"]["distributions"].pop()
    with pytest.raises(sbom.EvidenceError, match="GENERATED_INVENTORY_MISMATCH"):
        sbom.project(raw, receipt)
    raw, receipt = inputs()
    raw["dependencies"].pop()
    with pytest.raises(sbom.EvidenceError, match="DEPENDENCY_GRAPH_INCOMPLETE"):
        sbom.project(raw, receipt)
    raw, receipt = inputs()
    raw["dependencies"][0]["dependsOn"] = ["absent"]
    with pytest.raises(KeyError):
        sbom.project(raw, receipt)


def test_binding_changes_with_source_and_inventory_but_not_supplement_hashes(sbom):
    raw, receipt = inputs()
    original = sbom.project(raw, receipt)
    receipt["related_evidence"] = [{"sha256": "c" * 64}]
    assert sbom.project(raw, receipt) == original
    receipt["source"]["commit"] = "d" * 40
    assert sbom.project(raw, receipt) != original
    changed = copy.deepcopy(original)
    next(node for node in changed["dependencies"] if node["dependsOn"])["dependsOn"] = []
    sbom.schema_validate(changed)  # Schema alone cannot detect removed valid graph edges.
    with pytest.raises(sbom.EvidenceError, match="INTEGRITY_MISMATCH"):
        sbom.verify_document(changed, original)


def test_ambiguous_license_names_are_unresolved_not_approved(sbom):
    raw, receipt = inputs()
    raw["components"][0]["licenses"] = [{"license": {"name": "Unreviewed custom terms"}}]
    result = sbom.project(raw, receipt)
    component = result["components"][0]
    assert "licenses" not in component
    assert component["properties"][0]["value"] == "unresolved"


@pytest.mark.parametrize("drift", ["inventory", "runtime"])
def test_target_probe_refuses_drift_before_generator(sbom, monkeypatch, tmp_path, drift):
    _, receipt = inputs()
    probe = {"inventory": copy.deepcopy(receipt["inventory"]), **receipt["runtime"]}
    if drift == "inventory":
        probe["inventory"]["distributions"][1]["version"] = "3.0"
    else:
        probe["python"] = "3.12.14"
    commands = []

    def fake_probe(command, output):
        commands.append(command)
        output.write_bytes(sbom.encoded(probe))

    monkeypatch.setattr(sbom, "run_bounded", fake_probe)
    with pytest.raises(sbom.EvidenceError, match="TARGET_.*_MISMATCH"):
        sbom.generate_raw(Path("fixture-python"), receipt, tmp_path)
    assert len(commands) == 1  # Refused before invoking the generator on the wrong profile.


def test_projected_output_has_its_own_byte_limit(sbom, monkeypatch):
    raw, receipt = inputs()
    monkeypatch.setattr(sbom, "MAX_JSON", 64)
    with pytest.raises(sbom.EvidenceError, match="OUTPUT_LIMIT"):
        sbom.project(raw, receipt)
