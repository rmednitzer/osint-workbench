"""Offline checks: Markdown links, agent bridges, pins and canonical STATUS facts.

This intentionally checks a bounded Markdown subset, not remote link availability,
rendering, general prose truth or the complete security semantics of a workflow.
"""

import ast
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def prose(text, *, strip_inline=True):
    lines = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            lines.append("")
        elif fence is None:
            lines.append(re.sub(r"(`+).*?\1", "", line) if strip_inline else line.replace("`", ""))
        else:
            lines.append("")
    return "\n".join(lines)


def anchors(text):
    counts = Counter()
    result = set()
    for line in prose(text, strip_inline=False).splitlines():
        heading = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading:
            slug = re.sub(r"[^\w\- ]", "", heading[1].lower()).replace(" ", "-")
            result.add(slug + (f"-{counts[slug]}" if counts[slug] else ""))
            counts[slug] += 1
    return result


def markdown_links(root, path):
    failures = []
    text = prose(path.read_text())
    for target in re.findall(r"!?\[[^\]\n]*\]\(([^)\n]+)\)", text):
        target = target.strip().strip("<>")
        parts = urlsplit(target)
        if parts.scheme or parts.netloc:
            continue
        resolved = (path.parent / unquote(parts.path)).resolve() if parts.path else path.resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.exists():
            failures.append("missing-or-outside-local-link")
        elif parts.fragment and resolved.is_file() and resolved.suffix == ".md":
            if unquote(parts.fragment) not in anchors(resolved.read_text()):
                failures.append("missing-heading-anchor")
    return failures


def action_pins(text):
    failures = []
    for value in re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE):
        if value.startswith("./"):
            continue
        if value.startswith("docker://"):
            valid = re.fullmatch(r"docker://[^\s]+@sha256:[0-9a-f]{64}", value)
        else:
            valid = re.fullmatch(r"[^\s@]+/[\w./-]+@[0-9a-f]{40}", value)
        if not valid:
            failures.append("action-not-immutable")
    if re.search(r"^\s*pull_request_target\s*:", text, flags=re.MULTILINE):
        failures.append("privileged-pr-event-requires-review")
    return failures


def image_pins(text):
    return [
        "image-not-immutable"
        for image in re.findall(r"^\s*(?:FROM|image:)\s+([^\s#]+)", text, flags=re.MULTILINE)
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image)
    ]


def _assignment(scope, name):
    assignments = [
        node.value
        for node in ast.walk(scope)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    if len(assignments) != 1:
        raise ValueError
    return assignments[0]


def _function(tree, name):
    matches = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise ValueError
    return matches[0]


def _migration_paths(package, value):
    paths = ast.literal_eval(value)
    if not isinstance(paths, tuple) or not paths or len(set(paths)) != len(paths):
        raise ValueError
    for name in paths:
        if not isinstance(name, str):
            raise ValueError
        path = (package / name).resolve()
        if not path.is_relative_to(package.resolve()) or not path.is_file():
            raise ValueError
    return len(paths)


def _current_versions(root):
    """Read the implemented migration/payload declarations without importing application code."""
    package = root / "src/osint_workbench"
    database = ast.parse((package / "database.py").read_text())
    core = ast.literal_eval(_assignment(database, "SCHEMA_VERSION"))
    if type(core) is not int or core != _migration_paths(
        package, _assignment(database, "MIGRATIONS")
    ):
        raise ValueError
    retrieval = ast.parse((package / "vector_index.py").read_text())
    scripts = _assignment(_function(retrieval, "migrate_retrieval"), "scripts")
    if not isinstance(scripts, ast.ListComp) or len(scripts.generators) != 1:
        raise ValueError
    profile = _migration_paths(package, scripts.generators[0].iter)
    recovery = ast.parse((package / "recovery.py").read_text())
    payload = _assignment(_function(recovery, "checkpoint"), "payload")
    if not isinstance(payload, ast.Dict):
        raise ValueError
    formats = [
        ast.literal_eval(value)
        for key, value in zip(payload.keys, payload.values, strict=True)
        if isinstance(key, ast.Constant) and key.value == "format"
    ]
    if len(formats) != 1 or type(formats[0]) is not int or formats[0] < 1:
        raise ValueError
    return core, profile, formats[0]


def _register_count(values):
    numbers = [int(value) for value in values]
    if not numbers or sorted(numbers) != list(range(1, len(numbers) + 1)):
        raise ValueError
    return len(numbers)


def current_facts(root):
    """Check explicit current STATUS facts; historical receipts stay independent."""
    findings = []
    try:
        status = prose((root / "STATUS.md").read_text())
        versions = re.findall(
            r"Core schema\s+\*\*([0-9]+)\*\*, retrieval profile\s+\*\*([0-9]+)\*\*, "
            r"checkpoint format\s+\*\*([0-9]+)\*\*\.",
            status,
        )
        if len(versions) != 1 or tuple(map(int, versions[0])) != _current_versions(root):
            findings.append("current-schema-facts-mismatch")
        requirements = prose((root / "docs/assurance/requirements.md").read_text())
        scenarios = prose((root / "docs/testing/verification-plan.md").read_text())
        adrs = [
            match[1]
            for path in (root / "docs/adr").glob("*.md")
            if (match := re.fullmatch(r"([0-9]{4})-[a-z0-9-]+\.md", path.name))
        ]
        counts = (
            _register_count(adrs),
            _register_count(re.findall(r"^\|\s*R([0-9]+)\s*\|", requirements, re.MULTILINE)),
            _register_count(re.findall(r"^###\s+E([0-9]+):", scenarios, re.MULTILINE)),
        )
        claims = re.findall(
            r"([0-9]+) ADRs, ([0-9]+) requirements and ([0-9]+) full acceptance scenarios\.",
            status,
        )
        if len(claims) != 1 or tuple(map(int, claims[0])) != counts:
            findings.append("current-register-counts-mismatch")
    except (OSError, SyntaxError, ValueError, TypeError):
        findings.append("current-facts-unreadable-or-ambiguous")
    return findings


def main():
    selected = (
        subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
        )
        .decode()
        .split("\0")
    )
    findings = []
    findings.extend({"path": "STATUS.md", "category": category} for category in current_facts(ROOT))
    markdown = [name for name in selected if name.endswith(".md")]
    for name in markdown:
        for category in markdown_links(ROOT, ROOT / name):
            findings.append({"path": name, "category": category})
    for name in selected:
        if name.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
            content = (ROOT / name).read_text()
            for category in action_pins(content) + image_pins(content):
                findings.append({"path": name, "category": category})
        elif name.endswith("Dockerfile"):
            for category in image_pins((ROOT / name).read_text()):
                findings.append({"path": name, "category": category})
    if "@AGENTS.md" not in (ROOT / "CLAUDE.md").read_text().splitlines():
        findings.append({"path": "CLAUDE.md", "category": "missing-shared-import"})
    if not (ROOT / ".github/copilot-instructions.md").is_file():
        findings.append({"path": ".github/copilot-instructions.md", "category": "missing-bridge"})
    print(json.dumps({"markdown_files": len(markdown), "findings": findings}, sort_keys=True))
    return bool(findings)


if __name__ == "__main__":
    raise SystemExit(main())
