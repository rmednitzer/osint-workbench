"""Real local inode exclusion, ownership and connection-exit ordering."""

import threading

import pytest

from osint_workbench import evidence
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore


def test_same_instance_thread_does_not_inherit_exclusive_admission(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "objects")
    sha = store.put(b"synthetic evidence")
    monkeypatch.setattr(evidence, "ADMISSION_SECONDS", 0.03)
    errors = []

    def read():
        try:
            store.get(sha)
        except WorkbenchError as exc:
            errors.append(exc.code)

    with store.admission(exclusive=True):
        # A nested call in this thread uses the pinned root rather than locking
        # another descriptor against its own exclusive admission.
        assert store.get(sha) == b"synthetic evidence"
        thread = threading.Thread(target=read)
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive() and errors == ["EVIDENCE_STORE_BUSY"]
    assert store.get(sha) == b"synthetic evidence"


def test_independent_instance_and_alias_share_the_directory_inode(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "objects")
    other = EvidenceStore(store.root / ".")
    monkeypatch.setattr(evidence, "ADMISSION_SECONDS", 0.03)
    with store.admission(exclusive=True):
        with pytest.raises(WorkbenchError, match="^EVIDENCE_STORE_BUSY$"):
            other.put(b"not admitted")
    assert other.get(other.put(b"admitted")) == b"admitted"


def test_upgrade_and_unowned_acceptance_fail_closed(tmp_path):
    store = EvidenceStore(tmp_path / "objects")
    with pytest.raises(WorkbenchError, match="^EVIDENCE_ADMISSION_REQUIRED$"):
        store.require_transaction(object())
    with store.admission():
        with pytest.raises(WorkbenchError, match="^EVIDENCE_ADMISSION_UNSAFE$"):
            with store.admission(exclusive=True):
                pass
        with pytest.raises(WorkbenchError, match="^EVIDENCE_ACCEPTANCE_REQUIRED$"):
            store.require_transaction(object())


@pytest.mark.parametrize("commit_failure", [False, True])
def test_connection_exit_precedes_release_and_failure_releases_root(tmp_path, commit_failure):
    store = EvidenceStore(tmp_path / "objects")
    events = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            store.require_transaction(self)
            events.append("connection-exit-with-store-admitted")
            if commit_failure:
                raise RuntimeError("synthetic commit acknowledgement failure")

        def close(self):
            store.require_transaction(self)
            events.append("connection-close-with-store-admitted")

    try:
        with store.acceptance(Connection()) as conn:
            store.require_transaction(conn)
    except RuntimeError:
        assert commit_failure
    assert events == [
        "connection-exit-with-store-admitted",
        "connection-close-with-store-admitted",
    ]
    with pytest.raises(WorkbenchError, match="^EVIDENCE_ADMISSION_REQUIRED$"):
        store.admitted_root()
    with EvidenceStore(store.root).admission(exclusive=True):
        pass
