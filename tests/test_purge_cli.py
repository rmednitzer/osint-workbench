"""Installed CLI acceptance uses only a disposable fixture's scoped purge login."""

import json
import os
import subprocess
import sys

import pytest

from tests.test_record_purge import context as context
from tests.test_record_purge import retired_document

pytestmark = pytest.mark.integration


def test_installed_cli_plan_apply_and_explicit_receipt_replay(context):
    document = retired_document(context)
    path = context["tmp"] / "cli.owpurge"
    env = {**os.environ, "OW_PURGE_DSN": context["purger"]._dsn}

    def run(*args):
        process = subprocess.run(
            [sys.executable, "-m", "osint_workbench.cli", "purge", *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert process.returncode == 0, process.stderr
        assert "password" not in process.stdout.casefold()
        return json.loads(process.stdout)

    planned = run(
        "plan",
        "--file",
        str(path),
        "--document-id",
        document,
        "--operation-id",
        "cli-purge",
        "--actor",
        "synthetic-operator",
        "--rationale",
        "Synthetic CLI acceptance",
    )
    assert planned["counts"]["documents"] == 1
    args = ("apply", "--file", str(path), "--sha256", planned["sha256"])
    result = run(*args)
    assert result["sql_deleted"] and not result["replayed"]
    assert not result["physical_erasure"] and result["cas_objects_deleted"] == 0
    assert run(*args) == {**result, "replayed": True}
