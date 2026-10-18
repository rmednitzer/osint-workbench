import importlib.util
from pathlib import Path

import pytest


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


def test_dockerfile_and_workflow_images_require_content_identity():
    check = policy().image_pins
    assert check("FROM example.invalid/fixture:latest\n") == ["image-not-immutable"]
    image = "example.invalid/fixture:1@sha256:" + "a" * 64
    assert check("FROM " + image + "\n  image: " + image) == []


@pytest.fixture
def current_docs(tmp_path):
    package = tmp_path / "src/osint_workbench"
    (package / "migrations").mkdir(parents=True)
    for name in ("schema.sql", "retrieval.sql", "migrations/002.sql", "migrations/profile_002.sql"):
        (package / name).write_text("-- synthetic declaration fixture\n")
    (package / "database.py").write_text(
        "raise RuntimeError('source must not execute')\n"
        "SCHEMA_VERSION = 2\nMIGRATIONS = ('schema.sql', 'migrations/002.sql')\n"
    )
    (package / "vector_index.py").write_text(
        "def migrate_retrieval(dsn):\n"
        "    scripts = [read(p) for p in ('retrieval.sql', 'migrations/profile_002.sql')]\n"
    )
    (package / "recovery.py").write_text(
        "def checkpoint():\n    payload = {'format': 3, 'objects': unavailable()}\n"
    )
    (tmp_path / "docs/assurance").mkdir(parents=True)
    (tmp_path / "docs/testing").mkdir()
    (tmp_path / "docs/adr").mkdir()
    (tmp_path / "docs/assurance/requirements.md").write_text("| R01 | one |\n| R02 | two |\n")
    (tmp_path / "docs/testing/verification-plan.md").write_text("### E01: One\n### E02: Two\n")
    for name in ("0001-one.md", "0002-two.md"):
        (tmp_path / "docs/adr" / name).write_text("# Synthetic decision\n")
    (tmp_path / "STATUS.md").write_text(
        "Core schema **2**, retrieval profile **2**, checkpoint format **3**.\n"
        "2 ADRs, 2 requirements and 2 full acceptance scenarios.\n"
    )
    return tmp_path


def test_current_facts_read_source_without_importing_and_ignore_historical_examples(current_docs):
    with (current_docs / "STATUS.md").open("a") as stream:
        stream.write(
            "An earlier receipt used schema 1 and profile 1.\n"
            "`1 ADRs, 1 requirements and 1 full acceptance scenarios.`\n"
            "```md\nCore schema **1**, retrieval profile **1**, checkpoint format **1**.\n```\n"
        )
    assert policy().current_facts(current_docs) == []


@pytest.mark.parametrize("source", ["core", "retrieval", "checkpoint"])
def test_source_version_changes_require_current_status_update(current_docs, source):
    package = current_docs / "src/osint_workbench"
    if source == "core":
        path = package / "database.py"
        path.write_text(
            path.read_text()
            .replace("SCHEMA_VERSION = 2", "SCHEMA_VERSION = 3")
            .replace("'migrations/002.sql')", "'migrations/002.sql', 'migrations/003.sql')")
        )
        (package / "migrations/003.sql").write_text("-- additive fixture\n")
    elif source == "retrieval":
        path = package / "vector_index.py"
        path.write_text(
            path.read_text().replace(
                "'migrations/profile_002.sql')",
                "'migrations/profile_002.sql', 'migrations/profile_003.sql')",
            )
        )
        (package / "migrations/profile_003.sql").write_text("-- additive fixture\n")
    else:
        path = package / "recovery.py"
        path.write_text(path.read_text().replace("'format': 3", "'format': 4"))
    assert policy().current_facts(current_docs) == ["current-schema-facts-mismatch"]


@pytest.mark.parametrize("register", ["ADR", "requirement", "scenario"])
def test_register_growth_requires_current_count_update(current_docs, register):
    if register == "ADR":
        (current_docs / "docs/adr/0003-three.md").write_text("# Third decision\n")
    else:
        path = current_docs / (
            "docs/assurance/requirements.md"
            if register == "requirement"
            else "docs/testing/verification-plan.md"
        )
        with path.open("a") as stream:
            stream.write("| R03 | third |\n" if register == "requirement" else "### E03: Three\n")
    assert policy().current_facts(current_docs) == ["current-register-counts-mismatch"]


def test_missing_duplicate_or_gapped_register_ids_are_not_accepted_as_counts(current_docs):
    path = current_docs / "docs/assurance/requirements.md"
    for text in ("", "| R01 | one |\n| R01 | duplicate |\n", "| R01 | one |\n| R03 | gap |\n"):
        path.write_text(text)
        assert policy().current_facts(current_docs) == ["current-facts-unreadable-or-ambiguous"]


def test_missing_migration_declaration_does_not_silently_pass_a_status_claim(current_docs):
    (current_docs / "src/osint_workbench/migrations/002.sql").unlink()
    assert policy().current_facts(current_docs) == ["current-facts-unreadable-or-ambiguous"]
