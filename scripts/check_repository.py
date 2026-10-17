"""Offline repository checks: local Markdown links, agent bridges and action pins.

This intentionally checks a bounded Markdown subset, not remote link availability,
rendering, factual correctness or the complete security semantics of a workflow.
"""

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


def main():
    selected = (
        subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
        )
        .decode()
        .split("\0")
    )
    findings = []
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
