import importlib.util
from pathlib import Path


def policy():
    path = Path(__file__).resolve().parents[1] / "scripts/check_repository.py"
    spec = importlib.util.spec_from_file_location("repository_policy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_markdown_missing_file_and_anchor_are_detected(tmp_path):
    page = tmp_path / "page.md"
    page.write_text("# Example\n[bad](absent.md)\n[bad](#absent)\n")
    assert policy().markdown_links(tmp_path, page) == [
        "missing-or-outside-local-link",
        "missing-heading-anchor",
    ]


def test_markdown_valid_links_and_code_examples(tmp_path):
    page = tmp_path / "page.md"
    page.write_text(
        "# Example\n[ok](#example)\n`[sample](absent.md)`\n```md\n[example](absent.md)\n```\n"
    )
    assert policy().markdown_links(tmp_path, page) == []


def test_markdown_duplicate_heading_and_repository_escape(tmp_path):
    page = tmp_path / "page.md"
    page.write_text("# Example\n# Example\n[ok](#example-1)\n[bad](../absent.md)\n")
    assert policy().markdown_links(tmp_path, page) == ["missing-or-outside-local-link"]


def test_action_tags_are_rejected_and_immutable_references_pass():
    check = policy().action_pins
    assert check("  - uses: actions/checkout@v4\n") == ["action-not-immutable"]
    assert check("  - uses: actions/checkout@" + "a" * 40 + " # reviewed\n") == []
    assert check("  - uses: docker://example.invalid/image@sha256:" + "a" * 64) == []
    assert check("  pull_request_target:\n") == ["privileged-pr-event-requires-review"]
