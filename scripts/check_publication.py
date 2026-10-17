"""Fail closed on unclassified public files, URLs and common secret patterns.

This is a backstop, not an anonymity or exhaustive secret-detection guarantee.
Private exact values can be supplied in a JSON array outside the repository.
Findings contain categories and relative paths, never matching values.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
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
    "LICENSE",
    "README.md",
    "STATUS.md",
    "ROADMAP.md",
    "AGENTS.md",
    "CLAUDE.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
}
DOCUMENTATION_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "modelcontextprotocol.io",
    "www.postgresql.org",
    "www.rfc-editor.org",
    "www.psycopg.org",
    "csrc.nist.gov",
    "psas.scripts.mit.edu",
    "owasp.org",
    "genai.owasp.org",
    "www.apache.org",
    "onnxruntime.ai",
    "huggingface.co",
    "apache.org",
}
REGISTRY_HOSTS = {"pypi.org", "files.pythonhosted.org"}
URLS = re.compile(r'https?://[^\s"\x27<>),]+')
EMAILS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRETS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
]


def inspect_text(name: str, content: str, private_values=()) -> list[str]:
    findings = []
    if any(value and value.casefold() in content.casefold() for value in private_values):
        findings.append("private-identifier")
    if any(pattern.search(content) for pattern in SECRETS):
        findings.append("credential-pattern")
    if re.search(r"\b[\w.-]+\.(?:internal|lan|local)\b", content):
        findings.append("internal-domain")
    for email in EMAILS.findall(content):
        if not email.endswith((".invalid", "@noreply.github.com")) and not (
            name.startswith("tests/") and email.endswith(".example")
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
                name == "scripts/prepare_encoder.py"
                and host == "huggingface.co"
                and parts.path == "/"
            )
            or (
                name == "scripts/prepare_native.py"
                and host == "codeload.github.com"
                and parts.path == "/ggml-org/llama.cpp/tar.gz/"
            )
            or host.endswith(".invalid")
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    private_file = os.environ.get("OW_PRIVATE_DENYLIST")
    values = json.loads(Path(private_file).read_text()) if private_file else []
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        raise SystemExit("invalid private policy")
    findings = []
    for name in selected_files():
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
    print(
        json.dumps({"scanned_files": len(selected_files()), "findings": findings}, sort_keys=True)
    )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
