"""Native temporary Git histories; no actual repository identities are read."""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def checker():
    path = Path(__file__).resolve().parents[1] / "scripts/check_publication.py"
    spec = importlib.util.spec_from_file_location("commit_publication", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    environment = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "Synthetic Author",
        "GIT_AUTHOR_EMAIL": "author@example.invalid",
        "GIT_COMMITTER_NAME": "Synthetic Committer",
        "GIT_COMMITTER_EMAIL": "committer@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
    }

    def git(*arguments, input=None, overrides=None):
        result = subprocess.run(
            ["git", "-c", "commit.gpgsign=false", *arguments],
            cwd=repo,
            env={**environment, **(overrides or {})},
            input=input,
            capture_output=True,
            timeout=10,
            check=True,
        )
        return result.stdout.decode().strip()

    git("init", "--quiet")

    def commit(message="Synthetic change", **identities):
        git(
            "commit",
            "--quiet",
            "--allow-empty",
            "--file=-",
            input=message.encode(),
            overrides=identities,
        )
        return git("rev-parse", "HEAD")

    return repo, git, commit


def test_only_new_commit_metadata_is_scanned(checker, history):
    repo, _, commit = history
    canary = "synthetic-historical-private-host"
    base = commit(canary, GIT_AUTHOR_NAME=canary, GIT_AUTHOR_EMAIL="historical@unapproved.example")
    head = commit()
    result = checker.scan_commit_metadata(repo, base, [canary])
    assert result == {"scanned_commits": 1, "findings": []}
    assert canary not in json.dumps(result) and head != base


@pytest.mark.parametrize(
    "field",
    ["author-name", "committer-name", "author-email", "committer-email", "message", "trailer"],
)
def test_private_metadata_canaries_fail_without_printing_values(checker, history, field):
    repo, _, commit = history
    base = commit()
    canary = "synthetic-metadata-canary"
    email = canary + "@example.invalid"
    overrides, message = {}, "Synthetic change"
    if field == "author-name":
        overrides["GIT_AUTHOR_NAME"] = canary
    elif field == "committer-name":
        overrides["GIT_COMMITTER_NAME"] = canary
    elif field == "author-email":
        overrides["GIT_AUTHOR_EMAIL"] = email
    elif field == "committer-email":
        overrides["GIT_COMMITTER_EMAIL"] = email
    elif field == "message":
        message = "Synthetic change\n\n" + canary
    else:
        message = "Synthetic change\n\nCo-authored-by: Synthetic <" + email + ">"
    head = commit(message, **overrides)
    result = checker.scan_commit_metadata(repo, base, [canary], allow_base_identities=True)
    assert {"commit": head, "category": "private-identifier"} in result["findings"]
    assert canary not in json.dumps(result) and email not in json.dumps(result)


def test_base_identity_requires_explicit_opt_in_and_exact_match(checker, history):
    repo, _, commit = history
    email = "synthetic-public@unapproved.example"
    base = commit(GIT_AUTHOR_EMAIL=email)
    commit("Synthetic change\n\nCo-authored-by: Synthetic <" + email + ">", GIT_AUTHOR_EMAIL=email)
    assert checker.scan_commit_metadata(repo, base)["findings"][0]["category"] == "metadata-email"
    assert checker.scan_commit_metadata(repo, base, allow_base_identities=True)["findings"] == []
    assert checker.scan_commit_metadata(repo, base, [email], allow_base_identities=True)["findings"]
    commit(GIT_AUTHOR_EMAIL=email.upper())
    assert any(
        f["category"] == "metadata-email"
        for f in checker.scan_commit_metadata(repo, base, allow_base_identities=True)["findings"]
    )


def test_identity_from_older_history_is_not_inherited(checker, history):
    repo, _, commit = history
    email = "older-public@unapproved.example"
    commit(GIT_AUTHOR_EMAIL=email)
    base = commit()
    commit(GIT_AUTHOR_EMAIL=email)
    result = checker.scan_commit_metadata(repo, base, allow_base_identities=True)
    assert result["findings"][0]["category"] == "metadata-email"


@pytest.mark.parametrize(
    "email",
    [
        "automation@example.invalid",
        "web-flow@noreply.github.com",
        "noreply" + "@github.com",
        "123+synthetic[bot]@users.noreply.github.com",
    ],
)
def test_reserved_and_exact_github_noreply_identities_pass(checker, history, email):
    repo, _, commit = history
    base = commit()
    commit(GIT_AUTHOR_EMAIL=email, GIT_COMMITTER_EMAIL=email)
    assert checker.scan_commit_metadata(repo, base)["findings"] == []


@pytest.mark.parametrize(
    "email",
    [
        "synthetic@noreply.github.com.unapproved.example",
        "noreply" + "@github.com.unapproved.example",
    ],
)
def test_noreply_lookalike_is_not_admitted(checker, history, email):
    repo, _, commit = history
    base = commit()
    commit(GIT_AUTHOR_EMAIL=email)
    assert checker.scan_commit_metadata(repo, base)["findings"][0]["category"] == "metadata-email"


def test_invalid_or_nonancestor_revision_fails_safely(checker, history):
    repo, git, commit = history
    base = commit()
    git("checkout", "--quiet", "--orphan", "synthetic-other")
    commit("Synthetic unrelated root")
    for revision in (base, "--synthetic-private-revision"):
        result = checker.scan_commit_metadata(repo, revision)
        assert result["findings"] == [{"category": "metadata-revision-unavailable"}]
        assert "synthetic-private" not in json.dumps(result)


def test_merge_range_checks_side_commits_not_only_merge_message(checker, history):
    repo, git, commit = history
    base = commit()
    git("checkout", "--quiet", "-b", "synthetic-side")
    bad = commit("synthetic-side-canary")
    git("checkout", "--quiet", "--detach", base)
    commit("Synthetic main change")
    git("merge", "--quiet", "--no-ff", "synthetic-side", "-m", "Synthetic merge")
    result = checker.scan_commit_metadata(repo, base, ["synthetic-side-canary"])
    assert result["scanned_commits"] == 3
    assert {"commit": bad, "category": "private-identifier"} in result["findings"]


def test_agent_session_link_is_refused_before_merge_and_in_merge_metadata(
    checker, history, tmp_path
):
    repo, git, commit = history
    base = commit()
    git("checkout", "--quiet", "-b", "synthetic-fix")
    commit()
    assert checker.scan_commit_metadata(repo, base)["findings"] == []
    # Synthetic link only; never import an actual session identifier.
    session = "https:" + "//claude.ai/code/synthetic-session-canary"
    message = "Synthetic merge\n\nGenerated with an agent: " + session
    planned = tmp_path / "synthetic-message"
    planned.write_text(message)
    assert checker.scan_message_file(planned) == [
        {"path": "<planned-message>", "category": "unclassified-url"}
    ]
    git("checkout", "--quiet", "--detach", base)
    git("merge", "--quiet", "--no-ff", "synthetic-fix", "-m", message)
    head = git("rev-parse", "HEAD")
    result = checker.scan_commit_metadata(repo, base)
    assert result["findings"] == [{"commit": head, "category": "unclassified-url"}]
    assert session not in json.dumps(result)


@pytest.mark.parametrize(
    "kind", ["fifo", "symlink", "directory", "missing", "oversized", "utf8", "nul"]
)
def test_planned_message_refuses_unsafe_inputs_without_disclosure(checker, tmp_path, kind):
    message = tmp_path / "synthetic-message-path-canary"
    if kind == "fifo":
        os.mkfifo(message, mode=0o600)
    elif kind == "symlink":
        target = tmp_path / "synthetic-target"
        target.write_text("Synthetic message")
        message.symlink_to(target)
    elif kind == "directory":
        message.mkdir()
    elif kind == "oversized":
        with message.open("wb") as stream:
            stream.truncate(checker.MAX_COMMIT_BYTES + 1)
    elif kind in ("utf8", "nul"):
        message.write_bytes(b"\xff" if kind == "utf8" else b"Synthetic\0message")
    assert checker.scan_message_file(message) == [
        {"path": "<planned-message>", "category": "message-input-refused"}
    ]


def test_cli_preflights_public_message_and_applies_private_policy(
    checker, history, tmp_path, monkeypatch, capsys
):
    repo, _, commit = history
    commit()
    message = tmp_path / "synthetic-private-message-path"
    message.write_text("Synthetic public fix\n\nCo-authored-by: Automation <bot@example.invalid>")
    monkeypatch.setattr(checker, "ROOT", repo)
    monkeypatch.delenv("OW_PRIVATE_DENYLIST", raising=False)
    monkeypatch.setattr("sys.argv", ["check_publication.py", "--message-file", str(message)])
    assert checker.main() == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []
    canary = "synthetic-message-private-value"
    message.write_text(canary)
    policy = tmp_path / "synthetic-policy"
    policy.write_text(json.dumps([canary]))
    monkeypatch.setenv("OW_PRIVATE_DENYLIST", str(policy))
    assert checker.main() == 1
    output = capsys.readouterr().out
    assert json.loads(output)["findings"] == [
        {"path": "<planned-message>", "category": "private-identifier"}
    ]
    assert canary not in output and str(message) not in output and str(policy) not in output


def test_commit_count_and_byte_limits_fail_closed(checker, history, monkeypatch):
    repo, _, commit = history
    base = commit()
    commit("Synthetic first")
    commit("Synthetic second")
    monkeypatch.setattr(checker, "MAX_NEW_COMMITS", 1)
    assert checker.scan_commit_metadata(repo, base)["findings"] == [
        {"category": "metadata-limit-exceeded"}
    ]
    monkeypatch.setattr(checker, "MAX_NEW_COMMITS", 1000)
    monkeypatch.setattr(checker, "MAX_METADATA_BYTES", 1)
    assert checker.scan_commit_metadata(repo, base)["findings"] == [
        {"category": "metadata-limit-exceeded"}
    ]
    monkeypatch.setattr(checker, "MAX_METADATA_BYTES", 16 * 1024 * 1024)
    monkeypatch.setattr(checker, "MAX_COMMIT_BYTES", 1)
    assert checker.scan_commit_metadata(repo, base)["findings"] == [
        {"category": "metadata-limit-exceeded"}
    ]


def test_cli_uses_external_denylist_and_redacts_identity_message_and_policy_path(
    checker, history, tmp_path, monkeypatch, capsys
):
    repo, _, commit = history
    base = commit()
    canary = "synthetic-private-message"
    commit(canary, GIT_AUTHOR_NAME=canary)
    policy = tmp_path / "synthetic-private-policy.json"
    policy.write_text(json.dumps([canary]))
    monkeypatch.setenv("OW_PRIVATE_DENYLIST", str(policy))
    monkeypatch.setattr(checker, "ROOT", repo)
    monkeypatch.setattr("sys.argv", ["check_publication.py", "--base-revision", base])
    assert checker.main() == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["scanned_commits"] == 1
    assert any(f["category"] == "private-identifier" for f in result["findings"])
    assert canary not in captured.out + captured.err
    assert str(policy) not in captured.out + captured.err


def test_cli_without_base_reports_metadata_not_requested(checker, history, monkeypatch, capsys):
    repo, _, commit = history
    commit(GIT_AUTHOR_EMAIL="unapproved@unapproved.example")
    monkeypatch.delenv("OW_PRIVATE_DENYLIST", raising=False)
    monkeypatch.setattr(checker, "ROOT", repo)
    monkeypatch.setattr("sys.argv", ["check_publication.py"])
    assert checker.main() == 0
    assert json.loads(capsys.readouterr().out)["scanned_commits"] is None


def test_invalid_private_policy_fails_without_path_or_contents(
    checker, history, tmp_path, monkeypatch, capsys
):
    repo, _, _ = history
    policy = tmp_path / "synthetic-policy-path-canary.json"
    policy.write_text('{"synthetic-policy-content-canary":')
    monkeypatch.setenv("OW_PRIVATE_DENYLIST", str(policy))
    monkeypatch.setattr(checker, "ROOT", repo)
    monkeypatch.setattr("sys.argv", ["check_publication.py"])
    assert checker.main() == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"findings": [{"category": "invalid-private-policy"}]}
    assert "canary" not in captured.out + captured.err


def test_malformed_raw_commit_is_not_silently_truncated(checker, history):
    repo, git, commit = history
    base = commit()
    tree = git("rev-parse", "HEAD^{tree}")
    raw = (
        f"tree {tree}\nparent {base}\n"
        "author Synthetic <author@example.invalid> 946684800 +0000\n"
        "committer Synthetic <committer@example.invalid> 946684800 +0000\n\n"
    ).encode() + b"Synthetic message\0synthetic-hidden-canary"
    oid = git("hash-object", "-t", "commit", "--literally", "-w", "--stdin", input=raw)
    git("update-ref", "HEAD", oid)
    result = checker.scan_commit_metadata(repo, base, ["synthetic-hidden-canary"])
    assert result["findings"] == [{"category": "metadata-invalid-commit"}]
    assert "canary" not in json.dumps(result)


def test_metadata_git_invocations_cannot_use_even_local_fetch_transport(checker, history):
    repo, git, commit = history
    commit()
    # Control proves a functioning local synthetic remote; no Internet is involved.
    git("fetch", str(repo), "HEAD")
    with pytest.raises(checker.MetadataError, match="^metadata-revision-unavailable$"):
        checker._git(repo, ["fetch", str(repo), "HEAD"])


@pytest.mark.parametrize("kind", ["fifo", "symlink", "device", "directory", "missing", "oversized"])
def test_real_cli_refuses_unsafe_private_policy_files_without_hanging_or_disclosure(tmp_path, kind):
    policy = tmp_path / "synthetic-private-path-canary"
    if kind == "fifo":
        os.mkfifo(policy, mode=0o600)
    elif kind == "symlink":
        target = tmp_path / "synthetic-private-content-canary.json"
        target.write_text('["synthetic-private-content-canary"]')
        policy.symlink_to(target)
    elif kind == "device":
        policy = Path(os.devnull)
    elif kind == "directory":
        policy.mkdir()
    elif kind == "oversized":
        with policy.open("wb") as stream:
            stream.truncate(1024 * 1024 + 1)
    script = Path(__file__).resolve().parents[1] / "scripts/check_publication.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        env={**os.environ, "OW_PRIVATE_DENYLIST": str(policy)},
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"findings": [{"category": "invalid-private-policy"}]}
    assert result.stderr == b""
    assert b"canary" not in result.stdout + result.stderr
    assert str(policy).encode() not in result.stdout + result.stderr


@pytest.mark.parametrize("kind", ["directory", "valid", "malformed"])
def test_policy_descriptor_is_closed_on_guard_rejection_parse_failure_and_success(
    checker, tmp_path, monkeypatch, capsys, kind
):
    policy = tmp_path / "synthetic-policy"
    if kind == "directory":
        policy.mkdir()
    else:
        policy.write_text("[]" if kind == "valid" else "{")
    opened = []
    original_open = os.open

    def observed_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    monkeypatch.setattr(checker.os, "open", observed_open)
    monkeypatch.setattr(checker, "selected_files", lambda: [])
    monkeypatch.setenv("OW_PRIVATE_DENYLIST", str(policy))
    monkeypatch.setattr("sys.argv", ["check_publication.py"])
    assert checker.main() == (0 if kind == "valid" else 1)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    assert json.loads(capsys.readouterr().out)["findings"] == (
        [] if kind == "valid" else [{"category": "invalid-private-policy"}]
    )


def test_approved_connector_identity_is_metadata_only(checker, history):
    repo, _, commit = history
    email = "r.mednitzer" + "@outlook.com"
    base = commit()
    commit(GIT_AUTHOR_EMAIL=email, GIT_COMMITTER_EMAIL=email)
    assert checker.scan_commit_metadata(repo, base)["findings"] == []
    assert checker.scan_commit_metadata(repo, base, [email])["findings"]
    assert "email" in checker.inspect_text("docs/synthetic.md", email)
    commit(GIT_AUTHOR_EMAIL="other" + "@outlook.com")
    assert any(
        finding["category"] == "metadata-email"
        for finding in checker.scan_commit_metadata(repo, base)["findings"]
    )
