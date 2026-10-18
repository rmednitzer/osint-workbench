"""Explicit CI dependency preparation, separate from package imports and tests."""

import argparse
import hashlib
import io
import tarfile
import urllib.request
from pathlib import Path

REVISION = "620d2225cc436ab0b001e3200e590e3b286ef9ab"
ARCHIVE_SHA256 = "1d4a987d9bd048f6e93107e838026438df70fbde237fc0c69c63d600512b4bd9"
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
    print("Verified pinned native source; acceptance uses locally generated synthetic weights")


if __name__ == "__main__":
    main()
