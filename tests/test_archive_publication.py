"""Physical archive inventory and exposed metadata must not hide private canaries."""

import importlib.util
import io
import tarfile
import warnings
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def scanner():
    path = Path(__file__).resolve().parents[1] / "scripts/check_publication.py"
    spec = importlib.util.spec_from_file_location("archive_publication", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.scan_archive


def test_duplicate_wheel_member_is_rejected(scanner, tmp_path):
    path = tmp_path / "synthetic.whl"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("module.py", "synthetic-private-canary")
            archive.writestr("module.py", "benign")
    assert scanner(path, ["synthetic-private-canary"])


@pytest.mark.parametrize(
    "location", ["outer", "member", "archive-comment", "entry-comment", "extra", "directory"]
)
def test_wheel_metadata_and_directory_payload_cannot_bypass_scan(scanner, tmp_path, location):
    canary = "synthetic-private-canary"
    path = tmp_path / ((canary if location == "outer" else "synthetic") + ".whl")
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo(canary if location == "member" else "module.py")
        if location == "archive-comment":
            archive.comment = canary.encode()
        elif location == "entry-comment":
            info.comment = canary.encode()
        elif location == "extra":
            info.extra = b"\xff\xff" + len(canary).to_bytes(2, "little") + canary.encode()
        elif location == "directory":
            info.filename = "directory/"
        archive.writestr(info, canary if location == "directory" else "benign")
    findings = scanner(path, [canary])
    assert findings and canary not in str(findings)


def test_tar_pax_and_header_metadata_are_scanned(scanner, tmp_path):
    path, canary = tmp_path / "synthetic.tar.gz", "synthetic-private-canary"
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("package/module.py")
        info.uname = canary
        info.pax_headers = {"comment": canary}
        info.size = 6
        archive.addfile(info, io.BytesIO(b"benign"))
    findings = scanner(path, [canary])
    assert findings and canary not in str(findings)
