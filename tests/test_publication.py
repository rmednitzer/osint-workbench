import importlib.util
from pathlib import Path


def scanner():
    path = Path(__file__).resolve().parents[1] / "scripts/check_publication.py"
    spec = importlib.util.spec_from_file_location("publication", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect_text


def test_private_canary_never_appears_in_findings():
    check = scanner()
    value = "synthetic-sensitive-host"
    findings = check("src/example.py", "a " + value, [value])
    assert findings == ["private-identifier"] and value not in str(findings)


def test_urls_have_location_specific_policy():
    check = scanner()
    assert check("config/source.json", "https://example.invalid/feed") == []
    assert check("config/source.json", "https://unapproved.example/feed") == ["unclassified-url"]
    assert check("src/example.py", "https://github.com/example/repo") == ["unclassified-url"]
    assert check("docs/reference.md", "https://github.com/example/repo") == []
    assert check("uv.lock", "https://pypi.org/simple") == []
    assert check("src/example.py", "https://pypi.org/simple") == ["unclassified-url"]


def test_synthetic_email_and_credential_detection():
    check = scanner()
    assert check("x", "automation@example.invalid") == []
    assert check("x", "person@unapproved.example") == ["email"]
    assert check("x", "sk-proj-" + "A" * 40) == ["credential-pattern"]


def test_renovate_schema_allowance_is_exact_and_location_scoped():
    check = scanner()
    schema = "https:" + "//docs.renovatebot.com/renovate-schema.json"
    assert check("renovate.json", schema) == []
    assert check("src/example.py", schema) == ["unclassified-url"]
    assert check("renovate.json", "https:" + "//docs.renovatebot.com/other") == ["unclassified-url"]


def test_private_agent_ignore_patterns_do_not_allow_internal_hosts():
    check = scanner()
    patterns = "CLAUDE." + "local.md\n.claude/settings." + "local.json"
    assert check(".gitignore", patterns) == []
    assert check("config/example.json", patterns) == ["internal-domain"]
    assert check(".gitignore", patterns + "\nsynthetic." + "local") == ["internal-domain"]


def test_local_api_documentation_exception_is_exact_and_keeps_private_checks():
    check = scanner()
    url = "http:" + "//127.0.0.1:11434/v1/chat/completions"
    assert check("docs/local-inference-api.md", url) == []
    assert check("docs/other.md", url) == ["unclassified-url"]
    assert check("src/example.py", url) == ["unclassified-url"]
    assert check("docs/local-inference-api.md", url + "?secret=canary") == ["unclassified-url"]
    assert check("docs/local-inference-api.md", url.replace("11434", "8000")) == [
        "unclassified-url"
    ]
    assert check("docs/local-inference-api.md", url, ["127.0.0.1"]) == ["private-identifier"]
