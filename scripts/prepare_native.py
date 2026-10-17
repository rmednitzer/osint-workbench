"""Explicit CI dependency preparation, separate from package imports and tests."""

import argparse
import hashlib
import io
import tarfile
import urllib.request
from pathlib import Path

REVISION = "f2f667b02dc76d675395ae3b14546c8108d26387"
ARCHIVE_SHA256 = "f1be56733c3960c0261dd75f9e6d6776defbd3eb639e1cd76420842bd8106992"
URL = "https://codeload.github.com/ggml-org/llama.cpp/tar.gz/" + REVISION


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("preparation requires a new directory")
    with urllib.request.urlopen(URL, timeout=60) as response:
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != ARCHIVE_SHA256:
        raise SystemExit("native source integrity mismatch")
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(args.output, filter="data")
    print("Verified pinned native source; no models acquired")


if __name__ == "__main__":
    main()
