"""Run bounded offline type/security gates and prove their negative controls fail."""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(arguments):
    return subprocess.run(
        [sys.executable, "-m", *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )


def main():
    gates = (
        ("types", ["mypy", "--config-file", "pyproject.toml"]),
        ("security", ["ruff", "check", "--select", "S", "src/osint_workbench"]),
    )
    for name, arguments in gates:
        result = run(arguments)
        if result.returncode:
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            print(f"STATIC_GATE_FAILED={name}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory(prefix="ow-static-control-") as temporary:
        directory = Path(temporary)
        bad_type = directory / "bad_type.py"
        # The function is deliberately untyped: this also exercises check_untyped_defs.
        bad_type.write_text("def boundary():\n    payload: str = 1\n", encoding="utf-8")
        bad_security = directory / "bad_security.py"
        bad_security.write_text("eval(input())\n", encoding="utf-8")
        controls = (
            (
                "types",
                [
                    "mypy",
                    "--config-file",
                    "pyproject.toml",
                    "--no-incremental",
                    "--cache-dir",
                    str(directory / "mypy-cache"),
                    str(bad_type),
                ],
                "[assignment]",
            ),
            (
                "security",
                ["ruff", "check", "--select", "S", str(bad_security)],
                "S307",
            ),
        )
        for name, arguments, expected in controls:
            result = run(arguments)
            if result.returncode != 1 or expected not in result.stdout:
                print(f"STATIC_NEGATIVE_CONTROL_FAILED={name}", file=sys.stderr)
                return 1
    print("Static gates passed: four type-boundary modules, source S rules, two negative controls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
