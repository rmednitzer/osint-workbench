"""Sanitized operator diagnostics; configuration presence is not verification."""

import os
import platform
import sys
import sysconfig

from . import __version__
from .database import SCHEMA_VERSION, Database

_CONFIGURATION = (
    "OW_READER_DSN",
    "OW_EVIDENCE_ROOT",
    "OW_ENCODER_MANIFEST",
    "OW_RERANKER_MANIFEST",
)


def diagnose(*, check_reader=False):
    """Inspect this process; optionally validate reader authority and schema only.

    Never return environment values, paths, role names or exception messages.
    The default does not open application files, connect or execute inference.
    A matching runtime profile is not a qualification receipt.
    """
    try:
        release = platform.freedesktop_os_release()
    except (OSError, UnicodeError):
        release = {}
    ubuntu = release.get("VERSION_ID") if release.get("ID") == "ubuntu" else None
    ubuntu = ubuntu if ubuntu in ("24.04", "26.04") else "other_or_unknown"
    machine = platform.machine()
    architecture = machine if machine in ("x86_64", "aarch64") else "other_or_unknown"
    minor = sys.version_info[:2]
    standard_gil_build = sysconfig.get_config_var("Py_GIL_DISABLED") not in (1, "1")
    required_profile = (
        architecture == "x86_64"
        and standard_gil_build
        and platform.python_implementation() == "CPython"
        and ((ubuntu == "24.04" and minor == (3, 12)) or (ubuntu == "26.04" and minor == (3, 14)))
    )
    result = {
        "format": 1,
        "kind": "runtime_diagnostics",
        "application_version": __version__,
        "runtime": {
            "python": ".".join(str(n) for n in sys.version_info[:3]),
            "cpython": platform.python_implementation() == "CPython",
            "ubuntu_profile": ubuntu,
            "architecture": architecture,
            "standard_gil_build": standard_gil_build,
            "matches_required_profile": required_profile,
        },
        "configuration_present": {key: bool(os.environ.get(key)) for key in _CONFIGURATION},
        "reader": {
            "state": "not_checked",
            "expected_schema_version": SCHEMA_VERSION,
            "observed_schema_version": None,
        },
    }
    if not check_reader:
        return result
    reader = result["reader"]
    dsn = os.environ.get("OW_READER_DSN")
    if not dsn:
        reader["state"] = "not_configured"
        return result
    try:
        db = Database(dsn)
        with db.connect() as conn:
            db.validate_reader(connection=conn)
            row = conn.execute("SELECT version FROM ow.schema_status").fetchone()
        version = row["version"]
        if type(version) is not int or not 0 <= version <= 2**31 - 1:
            reader["state"] = "invalid_status"
        else:
            reader["observed_schema_version"] = version
            reader["state"] = "compatible" if version == SCHEMA_VERSION else "schema_mismatch"
    except Exception:
        # Even WorkbenchError codes are not forwarded from a backend boundary.
        reader["state"] = "unavailable_or_unsafe"
    return result
