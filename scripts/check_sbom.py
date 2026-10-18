"""Generate and verify a minimal public CycloneDX Python environment SBOM offline."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import resource
import subprocess
import sys
import tempfile
from pathlib import Path

from build_evidence import EvidenceError, checked, encoded, read_regular, source_identity
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from license_expression import ExpressionError, get_spdx_licensing
from packageurl import PackageURL

MAX_JSON = 4 * 1024 * 1024
MAX_COMPONENTS = 512
ROOT = Path(__file__).resolve().parents[1]
TARGET_PROBE = """
import json,platform,sys
sys.path.insert(0,sys.argv[1])
from build_evidence import inventory
print(json.dumps({'inventory':inventory(),'python':platform.python_version(),
                 'implementation':platform.python_implementation(),
                 'os':platform.freedesktop_os_release()['ID']+'-'+
                      platform.freedesktop_os_release()['VERSION_ID']}))
"""


def normalize(name):
    return re.sub(r"[-_.]+", "-", checked(name, r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")).lower()


def identity(item):
    return normalize(item["name"]), checked(item["version"], r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}")


def package_set(items):
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_COMPONENTS:
        raise EvidenceError("SBOM_COMPONENT_LIMIT")
    result = [identity(item) for item in items]
    if len(set(result)) != len(result) or len({name for name, _ in result}) != len(result):
        raise EvidenceError("SBOM_COMPONENT_AMBIGUOUS")
    return set(result)


def load_json(path):
    _, _, raw = read_regular(path, MAX_JSON, collect=True)
    return json.loads(raw)


def binding(receipt):
    core = {key: receipt[key] for key in ("source", "runtime", "workflow", "inventory")}
    for key in ("commit", "tree"):
        checked(core["source"][key], r"[0-9a-f]{40}")
    checked(core["runtime"]["python"], r"3\.[0-9]{1,2}\.[0-9]{1,3}")
    checked(core["runtime"]["os"], r"ubuntu-(24|26)\.04")
    checked(core["workflow"]["run_id"], r"[1-9][0-9]{0,23}")
    checked(core["workflow"]["run_attempt"], r"[1-9][0-9]{0,5}")
    package_set(core["inventory"]["distributions"])
    return core


def file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_JSON, MAX_JSON))


def run_bounded(command, output):
    with output.open("xb") as stream:
        subprocess.run(
            command,
            check=True,
            cwd=ROOT,
            env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1", "LC_ALL": "C.UTF-8"},
            stdout=stream,
            stderr=subprocess.DEVNULL,
            timeout=60,
            preexec_fn=file_limit,
        )


def generate_raw(python, receipt, temporary):
    # Both prepared interpreters trust site startup; -I is not a hostile-env sandbox.
    probe_path = temporary / "probe.json"
    run_bounded([str(python), "-I", "-c", TARGET_PROBE, str(ROOT / "scripts")], probe_path)
    probe = load_json(probe_path)
    if probe["inventory"] != receipt["inventory"]:
        raise EvidenceError("SBOM_TARGET_INVENTORY_MISMATCH")
    if any(probe[key] != receipt["runtime"][key] for key in ("python", "implementation", "os")):
        raise EvidenceError("SBOM_TARGET_RUNTIME_MISMATCH")
    raw_path = temporary / "raw.json"
    run_bounded(
        [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "environment",
            str(python),
            "--pyproject",
            str(ROOT / "pyproject.toml"),
            "--spec-version",
            "1.7",
            "--output-format",
            "JSON",
            "--output-reproducible",
            "--short-PURLs",
            "--validate",
        ],
        raw_path,
    )
    return load_json(raw_path)


def licenses(values):
    result = []
    licensing = get_spdx_licensing()
    for item in values:
        expression = item.get("expression")
        identifier = item.get("license", {}).get("id")
        value = expression or identifier
        if not isinstance(value, str) or len(value) > 512:
            continue
        try:
            parsed = licensing.parse(value, validate=True, strict=True)
        except ExpressionError:
            continue
        if expression:
            result.append({"expression": str(parsed), "acknowledgement": "declared"})
        else:
            result.append({"license": {"id": identifier, "acknowledgement": "declared"}})
    return sorted(result, key=lambda item: json.dumps(item, sort_keys=True))


def component(raw, *, application=False):
    name, version = identity(raw)
    purl = PackageURL(type="pypi", name=name, version=version).to_string()
    result = {
        "type": "application" if application else "library",
        "name": name,
        "version": version,
        "bom-ref": purl,
        "purl": purl,
    }
    if application:
        # A locally built application is not asserted to be a published PyPI package.
        result["bom-ref"] = f"urn:osint-workbench:application:{version}"
        del result["purl"]
    declarations = licenses(raw.get("licenses", []))
    if declarations:
        result["licenses"] = declarations
    result["properties"] = [
        {
            "name": "ow:license:declaration-status",
            "value": "recognized" if declarations else "unresolved",
        }
    ]
    return result


def schema_validate(document):
    if JsonStrictValidator(SchemaVersion.V1_7).validate_str(encoded(document).decode()) is not None:
        raise EvidenceError("SBOM_SCHEMA_INVALID")


def project(raw, receipt):
    core = binding(receipt)
    if raw.get("bomFormat") != "CycloneDX" or raw.get("specVersion") != "1.7":
        raise EvidenceError("SBOM_GENERATOR_FORMAT_MISMATCH")
    root_raw = raw["metadata"]["component"]
    root = component(root_raw, application=True)
    if root["name"] != "osint-workbench":
        raise EvidenceError("SBOM_ROOT_MISMATCH")
    installed = package_set(receipt["inventory"]["distributions"])
    raw_components = raw.get("components", [])
    if package_set([root_raw, *raw_components]) != installed:
        raise EvidenceError("SBOM_GENERATED_INVENTORY_MISMATCH")
    selected = [root, *(component(item) for item in raw_components)]
    references = {}
    for original, public in zip([root_raw, *raw_components], selected, strict=True):
        reference = original["bom-ref"]
        if reference in references:
            raise EvidenceError("SBOM_REFERENCE_AMBIGUOUS")
        references[reference] = public["bom-ref"]
    dependencies = []
    for node in raw["dependencies"]:
        # Missing/dangling references are a failure, never silently dropped.
        dependencies.append(
            {
                "ref": references[node["ref"]],
                "dependsOn": sorted({references[ref] for ref in node.get("dependsOn", [])}),
            }
        )
    if len(dependencies) != len(references) or {x["ref"] for x in dependencies} != set(
        references.values()
    ):
        raise EvidenceError("SBOM_DEPENDENCY_GRAPH_INCOMPLETE")
    properties = [{"name": "ow:binding:sha256", "value": hashlib.sha256(encoded(core)).hexdigest()}]
    for section, keys in (
        ("source", ("commit", "tree")),
        ("runtime", ("python", "os")),
        ("workflow", ("run_id", "run_attempt")),
    ):
        properties.extend(
            {"name": f"ow:{section}:{key}", "value": core[section][key]} for key in keys
        )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "component": root,
            "properties": properties,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "cyclonedx-bom",
                        "version": importlib.metadata.version("cyclonedx-bom"),
                    },
                    {
                        "type": "library",
                        "name": "cyclonedx-python-lib",
                        "version": importlib.metadata.version("cyclonedx-python-lib"),
                    },
                ]
            },
        },
        "components": sorted(selected[1:], key=lambda item: item["bom-ref"]),
        "dependencies": sorted(dependencies, key=lambda item: item["ref"]),
        # The Python metadata graph excludes bundled native/OS/model composition.
        "compositions": [{"aggregate": "incomplete", "assemblies": [root["bom-ref"]]}],
    }
    if len(encoded(document)) > MAX_JSON:
        raise EvidenceError("SBOM_OUTPUT_LIMIT")
    schema_validate(document)
    negative = dict(document, version="invalid-schema-negative-control")
    try:
        schema_validate(negative)
    except EvidenceError:
        pass
    else:
        raise EvidenceError("SBOM_SCHEMA_NEGATIVE_CONTROL_FAILED")
    return document


def verify_document(actual, expected):
    schema_validate(actual)
    if encoded(actual) != encoded(expected):
        raise EvidenceError("SBOM_INTEGRITY_MISMATCH")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "verify"))
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = load_json(args.manifest)
        source_identity(
            ROOT,
            {
                "OW_EVIDENCE_COMMIT": receipt["source"]["commit"],
                "OW_EVIDENCE_TREE": receipt["source"]["tree"],
            },
        )
        with tempfile.TemporaryDirectory(prefix="ow-sbom-") as temporary:
            raw = generate_raw(args.python.absolute(), receipt, Path(temporary))
            public = project(raw, receipt)
        if args.action == "generate":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("xb") as stream:
                stream.write(encoded(public))
        else:
            actual = load_json(args.output)
            verify_document(actual, public)
    except (
        EvidenceError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ) as error:
        category = str(error) if isinstance(error, EvidenceError) else "SBOM_OPERATION_FAILED"
        print(json.dumps({"status": "failed", "category": category}))
        return 1
    print(
        json.dumps(
            {
                "status": "generated" if args.action == "generate" else "verified",
                "specVersion": "1.7",
                "components": len(public["components"]) + 1,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
