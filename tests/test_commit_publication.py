"""Native temporary Git histories; no actual repository identities are read."""

import importlib.util
import json
import os
import subprocess
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
