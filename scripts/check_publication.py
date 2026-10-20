"""Fail closed on unclassified public files, URLs and common secret patterns.

This is a backstop, not an anonymity or exhaustive secret-detection guarantee.
Private exact values can be supplied in a JSON array outside the repository.
Findings contain categories and relative paths, never matching values.
"""

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_ROOTS = {
    "src",
    "tests",
    "scripts",
    "docs",
    "config",
    ".github",
}
ALLOWED_FILES = {
    ".gitignore",
    ".dockerignore",
    "pyproject.toml",
    "uv.lock",
    "build-constraints.txt",
    "LICENSE",
    "README.md",
    "STATUS.md",
    "ROADMAP.md",
    "AGENTS.md",
    "CLAUDE.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "renovate.json",
    # Reviewed opt-in container profile; private build inputs remain external.
    "containers/core/Dockerfile",
    "containers/core/compose.json",
    "containers/core/entrypoint.py",
    "containers/core/bootstrap.py",
    "containers/core/acceptance.py",
}
DOCUMENTATION_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "modelcontextprotocol.io",
    "py.sdk.modelcontextprotocol.io",
    "pypi.org",
    "www.postgresql.org",
    "www.rfc-editor.org",
    "docs.python.org",
    "www.encode.io",
    "www.psycopg.org",
    "csrc.nist.gov",
    "psas.scripts.mit.edu",
    "owasp.org",
    "genai.owasp.org",
    "www.apache.org",
    "onnxruntime.ai",
    "docs.ollama.com",
    "docs.vllm.ai",
    "huggingface.co",
    "apache.org",
    "man7.org",
    "docs.github.com",
    "docs.docker.com",
    "docs.renovatebot.com",
    "code.claude.com",
    "developers.openai.com",
}
REGISTRY_HOSTS = {"pypi.org", "files.pythonhosted.org"}
URLS = re.compile(r'https?://[^\s"\x27<>),]+')
EMAILS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
METADATA_EMAILS = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\[\]-]+@[A-Za-z0-9.-]+")
SECRETS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
]
MAX_NEW_COMMITS = 1000
MAX_COMMIT_BYTES = 256 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_PRIVATE_POLICY_BYTES = 1024 * 1024


class MetadataError(Exception):
    """Fixed public disposition; never include Git diagnostics or revision input."""


def _git(root, arguments, *, limit=MAX_COMMIT_BYTES):
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
                ["git", "--no-replace-objects", "--no-pager", *arguments],
                cwd=root,
                stdout=output,
                stderr=subprocess.DEVNULL,
                env={
                    **os.environ,
                    "GIT_NO_LAZY_FETCH": "1",
                    "GIT_ALLOW_PROTOCOL": "",
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_OPTIONAL_LOCKS": "0",
                },
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise MetadataError("metadata-git-unavailable") from None
        if result.returncode:
            raise MetadataError("metadata-revision-unavailable")
        output.seek(0)
        value = output.read(limit + 1)
    if len(value) > limit:
        raise MetadataError("metadata-limit-exceeded")
    return value


def _revision(root, revision):
    value = _git(root, ["rev-parse", "--verify", "--end-of-options", revision + "^{commit}"])
    if not re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\n", value):
        raise MetadataError("metadata-revision-unavailable")
    return value.decode().strip()


def _commit(root, revision):
    size = _git(root, ["cat-file", "-s", revision], limit=32)
    if not re.fullmatch(rb"[0-9]+\n", size):
        raise MetadataError("metadata-invalid-commit")
    if int(size) > MAX_COMMIT_BYTES:
        raise MetadataError("metadata-limit-exceeded")
    raw = _git(root, ["cat-file", "commit", revision], limit=MAX_COMMIT_BYTES)
    try:
        if b"\0" in raw:
            raise ValueError
        text = raw.decode("utf-8")
        headers, _ = text.split("\n\n", 1)
        emails = []
        for label in ("author", "committer"):
            rows = [line for line in headers.splitlines() if line.startswith(label + " ")]
            if len(rows) != 1:
                raise ValueError
            match = re.fullmatch(r"\w+ [^<>\n]* <([^<>\n]*)> -?[0-9]+ [+-][0-9]{4}", rows[0])
            if match is None:
                raise ValueError
            emails.append(match[1])
    except (UnicodeError, ValueError):
        raise MetadataError("metadata-invalid-commit") from None
    return text, emails, len(raw)


def _public_email(email, base_emails):
    if len(email) > 254 or METADATA_EMAILS.fullmatch(email) is None:
        return False
    local, domain = email.rsplit("@", 1)
    if len(local) > 64 or not domain or any(not label for label in domain.split(".")):
        return False
    return (
        email in base_emails
        or email == "noreply" + "@github.com"
        or (
            domain.casefold().endswith(".invalid")
            or domain.casefold() in {"noreply.github.com", "users.noreply.github.com"}
        )
    )


def _metadata_categories(text, private_values, base_emails=()):
    categories = set(inspect_text("docs/commit-metadata", text, private_values)) - {"email"}
    if any(not _public_email(e, base_emails) for e in METADATA_EMAILS.findall(text)):
        categories.add("metadata-email")
    return sorted(categories)


def scan_message_file(path, private_values=()):
    """Preflight an exact planned public message without creating a Git object.

    Final-component guard only; callers protect parents and custody through use.
    No identity inheritance: use reserved public identities in optional trailers.
    Diagnostics never reproduce the selected path or message.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_COMMIT_BYTES:
                raise ValueError
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read(MAX_COMMIT_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_COMMIT_BYTES or b"\0" in raw:
            raise ValueError
        categories = _metadata_categories(raw.decode("utf-8"), private_values)
    except (OSError, ValueError):
        categories = ["message-input-refused"]
    return [{"path": "<planned-message>", "category": category} for category in categories]


def scan_commit_metadata(root, base_revision, private_values=(), *, allow_base_identities=False):
    """Only commits newly reachable from HEAD, excluding an explicitly trusted base.

    Optional inherited emails come from the base commit itself, never all history.
    The denylist still scans the original complete text before email admission.
    """
    try:
        base, head = _revision(root, base_revision), _revision(root, "HEAD")
        _git(root, ["merge-base", "--is-ancestor", base, head])
        revisions = (
            _git(root, ["rev-list", f"--max-count={MAX_NEW_COMMITS + 1}", base + ".." + head])
            .decode()
            .splitlines()
        )
        if len(revisions) > MAX_NEW_COMMITS:
            raise MetadataError("metadata-limit-exceeded")
        base_emails = set(_commit(root, base)[1]) if allow_base_identities else set()
        findings, total = [], 0
        for revision in revisions:
            text, identities, size = _commit(root, revision)
            total += size
            if total > MAX_METADATA_BYTES:
                raise MetadataError("metadata-limit-exceeded")
            categories = set(_metadata_categories(text, private_values, base_emails))
            if any(not _public_email(e, base_emails) for e in identities):
                categories.add("metadata-email")
            findings.extend({"commit": revision, "category": c} for c in sorted(categories))
        return {"scanned_commits": len(revisions), "findings": findings}
    except MetadataError as exc:
        return {"scanned_commits": 0, "findings": [{"category": str(exc)}]}


def inspect_text(name: str, content: str, private_values=(), *, verified_notice=False) -> list[str]:
    findings = []
    if any(value and value.casefold() in content.casefold() for value in private_values):
        findings.append("private-identifier")
    if any(pattern.search(content) for pattern in SECRETS):
        findings.append("credential-pattern")
    domain_text = "\n".join(
        line
        for line in content.splitlines()
        if not (
            name == ".gitignore"
            and line in {"CLAUDE." + "local.md", ".claude/settings." + "local.json"}
        )
    )
    if re.search(r"\b[\w.-]+\.(?:internal|lan|local)\b", domain_text):
        findings.append("internal-domain")
    for email in EMAILS.findall(content):
        if (
            email != "noreply" + "@github.com"
            and not email.endswith((".invalid", "@noreply.github.com"))
            and not (name.startswith("tests/") and email.endswith(".example"))
        ):
            findings.append("email")
    for url in URLS.findall(content):
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
        except ValueError:
            findings.append("invalid-url")
            continue
        allowed = (
            (
                verified_notice
                and name == "missing-wheel-notices.txt"
                and url
                in {
                    "http:" + "//www.apache.org/licenses/",
                    "http:" + "//www.apache.org/licenses/LICENSE-2.0",
                }
            )
            or (
                name == "renovate.json"
                and url == "https:" + "//docs.renovatebot.com/renovate-schema.json"
            )
            or (
                name == "scripts/prepare_encoder.py"
                and host == "huggingface.co"
                and parts.path == "/"
            )
            or (
                name == "scripts/prepare_native.py"
                and host == "codeload.github.com"
                and parts.path == "/ggml-org/llama.cpp/tar.gz/"
            )
            or (
                name == "docs/local-inference-api.md"
                and url == "http:" + "//127.0.0.1:11434/v1/chat/completions"
            )
            or host.endswith(".invalid")
            or (
                name == ".github/workflows/compose-core.yml"
                and url == "https:" + "//pypi.org/simple"
            )
            or (name == "uv.lock" and host in REGISTRY_HOSTS)
            or (name == "pyproject.toml" and host == "pypi.org" and parts.path == "/simple")
            or (
                (name.startswith("docs/") or Path(name).name == "LICENSE")
                and host in DOCUMENTATION_HOSTS
            )
            or (
                name.startswith("tests/")
                and url
                in {
                    "https:" + "//unapproved.example/feed",
                    "https:" + "//github.com/example/repo",
                    "https:" + "//pypi.org/simple",
                }
            )
        )
        synthetic_auth = name.startswith("tests/") and host.endswith(".invalid")
        if ((parts.username or parts.password) and not synthetic_auth) or not allowed:
            findings.append("unclassified-url")
    return sorted(set(findings))


def selected_files():
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True)
    return [name for name in result.stdout.decode().split("\0") if name]


def scan_generated_evidence(directory, private_values=()):
    """Scan exact generated sets; notice URLs require byte-exact upstream proof."""
    from build_evidence import EvidenceError, read_regular
    from build_notices import NoticeError, bundle

    assurance = {
        "sbom.cdx.json",
        "licence-review.json",
        "native-review.json",
        "missing-wheel-notices.txt",
    }
    receipts = {"manifest.json", "manifest.sha256"}
    findings = []
    try:
        names = {path.name for path in directory.iterdir()}
        if names not in (assurance, receipts):
            return [{"path": "<generated-evidence>", "category": "invalid-evidence-set"}]
        for name in sorted(names):
            _, _, data = read_regular(directory / name, 4 * 1024 * 1024, collect=True)
            verified_notice = False
            if name == "missing-wheel-notices.txt":
                _, _, policy = read_regular(
                    ROOT / "docs/security/dependency-licences.json", 4 * 1024 * 1024, collect=True
                )
                if data == bundle(policy, root=ROOT):
                    verified_notice = True
                else:
                    findings.append({"path": name, "category": "notice-provenance-mismatch"})
            findings.extend(
                {"path": name, "category": category}
                for category in inspect_text(
                    name, data.decode("utf-8"), private_values, verified_notice=verified_notice
                )
            )
    except (EvidenceError, NoticeError, OSError, ValueError):
        findings.append({"path": "<generated-evidence>", "category": "evidence-input-refused"})
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--evidence", type=Path, action="append", default=[])
    parser.add_argument("--base-revision", help="Explicit reviewed ancestor; scan only base..HEAD")
    parser.add_argument("--allow-base-identities", action="store_true")
    parser.add_argument(
        "--message-file", type=Path, help="Preflight an exact planned public message"
    )
    args = parser.parse_args()
    if args.allow_base_identities and args.base_revision is None:
        parser.error("--allow-base-identities requires --base-revision")
    private_file = os.environ.get("OW_PRIVATE_DENYLIST")
    try:
        if private_file:
            fd = os.open(private_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PRIVATE_POLICY_BYTES:
                    raise ValueError
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    raw = stream.read(MAX_PRIVATE_POLICY_BYTES + 1)
            finally:
                os.close(fd)
            if len(raw) > MAX_PRIVATE_POLICY_BYTES:
                raise ValueError
            values = json.loads(raw.decode("utf-8"))
        else:
            values = []
        if (
            not isinstance(values, list)
            or len(values) > 10000
            or any(not isinstance(v, str) or len(v) > 4096 for v in values)
        ):
            raise ValueError
    except (OSError, ValueError, UnicodeError, RecursionError):
        print(json.dumps({"findings": [{"category": "invalid-private-policy"}]}))
        return 1
    findings = []
    files = selected_files()
    for name in files:
        path = ROOT / name
        if (
            name.split("/")[0] not in ALLOWED_ROOTS and name not in ALLOWED_FILES
        ) or path.is_symlink():
            findings.append({"path": name, "category": "unselected-path"})
            continue
        try:
            content = path.read_text()
        except (UnicodeError, OSError):
            findings.append({"path": name, "category": "unreviewed-binary-or-missing"})
            continue
        findings.extend({"path": name, "category": c} for c in inspect_text(name, content, values))
    if args.artifacts:
        for artifact in sorted(args.artifacts.iterdir()):
            if artifact.name == ".gitignore" and artifact.read_bytes() == b"*":
                continue
            members = []
            if artifact.suffix == ".whl":
                with zipfile.ZipFile(artifact) as archive:
                    members = [
                        (n, archive.read(n)) for n in archive.namelist() if not n.endswith("/")
                    ]
            elif artifact.name.endswith(".tar.gz"):
                with tarfile.open(artifact) as archive:
                    for member in archive.getmembers():
                        if member.issym() or member.islnk():
                            findings.append({"path": artifact.name, "category": "archive-link"})
                        elif member.isfile():
                            stream = archive.extractfile(member)
                            members.append((member.name, stream.read()))
            else:
                findings.append({"path": artifact.name, "category": "unknown-artifact"})
            for name, data in members:
                if ".." in Path(name).parts or Path(name).is_absolute():
                    findings.append({"path": artifact.name, "category": "archive-path"})
                # Treat archive paths as package content, not documentation by default.
                relative = name.split("/", 1)[-1] if artifact.name.endswith(".tar.gz") else name
                try:
                    content = data.decode()
                except UnicodeError:
                    findings.append({"path": artifact.name, "category": "unreviewed-binary"})
                    continue
                findings.extend(
                    {"path": artifact.name, "category": c}
                    for c in inspect_text(relative, content, values)
                )
    for directory in args.evidence:
        findings.extend(scan_generated_evidence(directory, values))
    if args.message_file is not None:
        findings.extend(scan_message_file(args.message_file, values))
    metadata = (
        scan_commit_metadata(
            ROOT, args.base_revision, values, allow_base_identities=args.allow_base_identities
        )
        if args.base_revision is not None
        else {"scanned_commits": None, "findings": []}
    )
    findings.extend(metadata["findings"])
    print(
        json.dumps(
            {
                "scanned_files": len(files),
                "scanned_commits": metadata["scanned_commits"],
                "findings": findings,
            },
            sort_keys=True,
        )
    )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
