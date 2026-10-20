"""Pure custody guards; actual container acceptance is explicitly opt-in."""

import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_compose_cleanup_refuses_missing_or_foreign_ownership():
    module = runpy.run_path(str(ROOT / "scripts/test_compose_core.py"))
    ownership = module["ownership"]
    label = module["LABEL"]
    for resource in ({}, {"Labels": {label: "other"}}, {"Config": {"Labels": {}}}):
        with pytest.raises(module["Rejected"], match="PROFILE_RESOURCE_OWNERSHIP"):
            ownership(resource, "expected")
    ownership({"Labels": {label: "expected"}}, "expected")
    ownership({"Config": {"Labels": {label: "expected"}}}, "expected")


def test_compose_copy_refuses_linked_or_oversized_private_objects(tmp_path):
    module = runpy.run_path(str(ROOT / "containers/core/bootstrap.py"))
    regular = module["regular"]
    source = tmp_path / "source"
    source.write_bytes(b"synthetic")
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(RuntimeError, match="PROFILE_FILE_INVALID"):
        regular(link, 100)
    with pytest.raises(RuntimeError, match="PROFILE_FILE_INVALID"):
        regular(source, 2)
    link.unlink()
    link.hardlink_to(source)
    with pytest.raises(RuntimeError, match="PROFILE_FILE_INVALID"):
        regular(source, 100)
    link.unlink()
    assert regular(source, 100) == b"synthetic"


def test_compose_cleanup_failure_preserves_primary_error():
    module = runpy.run_path(str(ROOT / "scripts/test_compose_core.py"))
    error = module["Rejected"]
    primary = error("PROFILE_PRIMARY_FAILURE")

    def cleanup():
        raise error("PROFILE_COMMAND_FAILED_DOCKER_VOLUME_RM")

    with pytest.raises(error) as raised, module["cleanup_guard"](cleanup):
        raise primary
    assert raised.value is primary
    assert primary.__notes__ == ["PROFILE_CLEANUP_FAILED:PROFILE_COMMAND_FAILED_DOCKER_VOLUME_RM"]
    name = module["command_name"]
    assert (
        name(["docker", "compose", "--file", "/private/location", "down"]) == "DOCKER_COMPOSE_DOWN"
    )
    assert name(["docker", "volume", "rm", "private-volume"]) == "DOCKER_VOLUME_RM"
