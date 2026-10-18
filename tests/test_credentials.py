"""Exercise real filesystem boundaries without provisioning operational secrets."""

import os
import traceback
from pathlib import Path

import pytest
from pydantic import ValidationError

from osint_workbench.credentials import (
    MAX_CREDENTIAL_BYTES,
    CredentialError,
    CredentialRef,
    resolve_credential,
)

CANARY = "fixture-token-credential-canary"
CANARY_BYTES = CANARY.encode()


def _credential(tmp_path, payload=CANARY_BYTES):
    path = tmp_path / "operator-token"
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def _file_reference(path):
    return CredentialRef(kind="file", path=str(path))


def test_file_token_is_secret_and_reference_repr_hides_private_path(tmp_path, caplog):
    path = _credential(tmp_path)
    reference = _file_reference(path)
    secret = resolve_credential(reference)
    assert secret.get_secret_value() == CANARY
    for public in (repr(reference), str(reference), repr(secret), str(secret), caplog.text):
        assert CANARY not in public
        assert str(path) not in public


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_read_only_and_read_write_private_credentials(tmp_path, mode):
    path = _credential(tmp_path)
    path.chmod(mode)
    assert resolve_credential(_file_reference(path)).get_secret_value() == CANARY


def test_systemd_explicit_directory_resolves_named_token(tmp_path):
    path = _credential(tmp_path)
    reference = CredentialRef(kind="systemd", name=path.name)
    assert (
        resolve_credential(reference, credentials_directory=tmp_path).get_secret_value() == CANARY
    )


def test_systemd_environment_selects_directory_only(tmp_path, monkeypatch):
    path = _credential(tmp_path)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    monkeypatch.setenv(path.name, "unrelated-environment-canary")
    assert (
        resolve_credential(CredentialRef(kind="systemd", name=path.name)).get_secret_value()
        == CANARY
    )


def test_systemd_missing_directory_never_falls_back_to_named_environment(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.setenv("example-token", CANARY)
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNAVAILABLE$"):
        resolve_credential(CredentialRef(kind="systemd", name="example-token"))


@pytest.mark.parametrize(
    "fields",
    [
        {"kind": "environment", "name": "OW_TOKEN"},
        {"kind": "systemd"},
        {"kind": "systemd", "name": "../token"},
        {"kind": "systemd", "name": "token", "path": "/private/token"},
        {"kind": "file"},
        {"kind": "file", "path": "relative-token"},
        {"kind": "file", "path": "/private/../token"},
        {"kind": "file", "path": "/private/token", "name": "token"},
        {"kind": "file", "path": "/private/token", "value": CANARY},
        {"kind": "file", "path": "/private/\x00token"},
    ],
)
def test_reference_rejects_ambiguous_unsafe_and_value_configuration(fields):
    with pytest.raises(ValidationError) as failure:
        CredentialRef.model_validate(fields)
    assert CANARY not in str(failure.value)
    assert "/private" not in str(failure.value)


@pytest.mark.parametrize(
    "payload", [b"", b"with space", b"token\n", b"token\r\n", b"a\x00b", b"\xff"]
)
def test_rejects_empty_whitespace_binary_and_header_injection(tmp_path, payload):
    path = _credential(tmp_path, payload)
    with pytest.raises(CredentialError, match="^CREDENTIAL_INVALID$"):
        resolve_credential(_file_reference(path))


def test_token_size_boundary(tmp_path):
    path = _credential(tmp_path, b"x" * MAX_CREDENTIAL_BYTES)
    assert len(resolve_credential(_file_reference(path)).get_secret_value()) == MAX_CREDENTIAL_BYTES
    path.write_bytes(b"x" * (MAX_CREDENTIAL_BYTES + 1))
    with pytest.raises(CredentialError, match="^CREDENTIAL_INVALID$"):
        resolve_credential(_file_reference(path))


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o606, 0o666, 0o700, 0o4600])
def test_refuses_group_or_other_access(tmp_path, mode):
    path = _credential(tmp_path)
    path.chmod(mode)
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNSAFE$"):
        resolve_credential(_file_reference(path))


def test_refuses_writable_nonsticky_ancestor(tmp_path):
    path = _credential(tmp_path)
    tmp_path.chmod(0o777)
    try:
        with pytest.raises(CredentialError, match="^CREDENTIAL_UNSAFE$"):
            resolve_credential(_file_reference(path))
    finally:
        tmp_path.chmod(0o700)


def test_refuses_symlink_leaf_and_symlink_ancestor(tmp_path):
    path = _credential(tmp_path)
    linked = tmp_path / "linked-token"
    linked.symlink_to(path)
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNAVAILABLE$"):
        resolve_credential(_file_reference(linked))
    linked_directory = tmp_path / "linked-directory"
    linked_directory.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNAVAILABLE$"):
        resolve_credential(_file_reference(linked_directory / path.name))


def test_fifo_and_directory_refused_without_blocking(tmp_path):
    pipe = tmp_path / "pipe-token"
    os.mkfifo(pipe, 0o600)
    for path in (pipe, tmp_path):
        with pytest.raises(CredentialError, match="^CREDENTIAL_UNSAFE$"):
            resolve_credential(_file_reference(path))


def test_hardlinked_credentials_refused(tmp_path):
    path = _credential(tmp_path)
    os.link(path, tmp_path / "second-link")
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNSAFE$"):
        resolve_credential(_file_reference(path))


def test_diagnostics_exclude_private_path_and_secret(tmp_path, caplog):
    path = tmp_path / CANARY
    with pytest.raises(CredentialError) as failure:
        resolve_credential(_file_reference(path))
    diagnostic = "".join(traceback.format_exception(failure.value))
    assert CANARY not in diagnostic
    assert str(tmp_path) not in diagnostic
    assert CANARY not in caplog.text
    assert str(failure.value) == "CREDENTIAL_UNAVAILABLE"


def test_systemd_directory_must_be_absolute(tmp_path):
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNSAFE$"):
        resolve_credential(
            CredentialRef(kind="systemd", name="token"), credentials_directory=Path("relative")
        )


def test_file_owner_must_be_root_or_service_uid(tmp_path, monkeypatch):
    # Exercise owner rejection even on runners without privilege to chown fixtures.
    path = _credential(tmp_path)
    real_fstat = os.fstat

    def different_leaf_owner(descriptor):
        info = real_fstat(descriptor)
        if info.st_ino == path.stat().st_ino:
            fields = list(info)
            fields[4] = max(os.geteuid(), 0) + 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(os, "fstat", different_leaf_owner)
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNSAFE$"):
        resolve_credential(_file_reference(path))


def test_credential_error_does_not_accept_arbitrary_diagnostics():
    with pytest.raises(ValueError, match="^INVALID_CREDENTIAL_ERROR_CODE$"):
        CredentialError(CANARY)


def test_file_changed_during_read_refused(tmp_path, monkeypatch):
    path = _credential(tmp_path)
    real_read = os.read
    changed = False

    def replace_after_read(descriptor, count):
        nonlocal changed
        content = real_read(descriptor, count)
        if not changed:
            changed = True
            path.write_bytes(b"replacement-token-of-different-length")
        return content

    monkeypatch.setattr(os, "read", replace_after_read)
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNSAFE$"):
        resolve_credential(_file_reference(path))


def test_unsafe_systemd_directory_does_not_fall_back_to_file(tmp_path, monkeypatch):
    path = _credential(tmp_path)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "missing"))
    monkeypatch.setenv(path.name, CANARY)
    with pytest.raises(CredentialError, match="^CREDENTIAL_UNAVAILABLE$"):
        resolve_credential(CredentialRef(kind="systemd", name=path.name))
