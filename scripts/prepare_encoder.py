"""Explicit pinned public artifact preparation; never imported by runtime or tests.

The licence acknowledgement concerns the published Apache-2.0 model card. It is
not a legal opinion or a claim about the complete training-data licence lineage.
This prepares bytes only: it does not accept the graph or activate an index.
"""

import argparse
import hashlib
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path

REPOSITORY = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
REVISION = "e8f8c211226b894fcb81acc59f3b34ba3efd5f42"
BASE_URL = "https://huggingface.co/" + REPOSITORY + "/resolve/" + REVISION + "/"
ARTIFACTS = (
    (
        "onnx/model.onnx",
        "model.onnx",
        470301610,
        "10f7a088420252b26caf819236ca2c9d2987afd0fc06fec7553b542a5655a05a",
    ),
    (
        "tokenizer.json",
        "tokenizer.json",
        9081518,
        "2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8",
    ),
)
ALLOWED_HOSTS = frozenset(
    {
        "huggingface.co",
        "cdn-lfs.huggingface.co",
        "cdn-lfs-us-1.hf.co",
        "cdn-lfs-eu-1.hf.co",
        "cas-bridge.xethub.hf.co",
    }
)
FILE_TIMEOUT = 180
READ_TIMEOUT = 30
BLOCK_SIZE = 1024 * 1024


class PreparationError(Exception):
    pass


def check_url(url):
    parsed = urllib.parse.urlsplit(url)
    try:
        allowed = (
            parsed.scheme == "https"
            and parsed.hostname in ALLOWED_HOSTS
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        )
    except ValueError:
        allowed = False
    if not allowed:
        raise PreparationError("DOWNLOAD_DESTINATION_REFUSED")


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    max_repeats = 2
    max_redirections = 5

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


@contextmanager
def file_deadline():
    # Linux is the supported preparation/execution environment. The process-wide
    # alarm also bounds DNS, headers and a stalled read, not just loop iterations.
    def expired(signum, frame):
        raise PreparationError("DOWNLOAD_TIMEOUT")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, FILE_TIMEOUT)
    try:
        yield time.monotonic() + FILE_TIMEOUT
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def promote(directory_fd, name, write):
    staging = ".staging-" + uuid.uuid4().hex
    fd = os.open(
        staging,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link promotion is atomic and refuses an existing destination.
        os.link(
            staging,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.fsync(directory_fd)
    finally:
        os.unlink(staging, dir_fd=directory_fd)
        os.fsync(directory_fd)


def fetch(opener, directory_fd, artifact):
    remote, local, expected_bytes, expected_sha = artifact
    url = BASE_URL + remote
    check_url(url)

    def write(stream):
        hasher = hashlib.sha256()
        size = 0
        with file_deadline() as deadline:
            request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
            with opener.open(request, timeout=READ_TIMEOUT) as response:
                check_url(response.geturl())
                if response.status != 200:
                    raise PreparationError("DOWNLOAD_RESPONSE_REFUSED")
                encoding = response.headers.get("Content-Encoding", "identity")
                if encoding.lower() != "identity":
                    raise PreparationError("DOWNLOAD_ENCODING_REFUSED")
                length = response.headers.get("Content-Length")
                if length is not None and length != str(expected_bytes):
                    raise PreparationError("ARTIFACT_SIZE_MISMATCH")
                while True:
                    if time.monotonic() >= deadline:
                        raise PreparationError("DOWNLOAD_TIMEOUT")
                    block = response.read(min(BLOCK_SIZE, expected_bytes - size + 1))
                    if not block:
                        break
                    size += len(block)
                    if size > expected_bytes:
                        raise PreparationError("ARTIFACT_SIZE_MISMATCH")
                    hasher.update(block)
                    stream.write(block)
        if size != expected_bytes or hasher.hexdigest() != expected_sha:
            raise PreparationError("ARTIFACT_INTEGRITY_MISMATCH")

    promote(directory_fd, local, write)


def manifest(directory):
    return {
        "schema_version": 1,
        "model_path": str(directory / "model.onnx"),
        "tokenizer_path": str(directory / "tokenizer.json"),
        "model_sha256": ARTIFACTS[0][3],
        "tokenizer_sha256": ARTIFACTS[1][3],
        "space": {
            "model_revision": ARTIFACTS[0][3],
            "tokenizer_revision": ARTIFACTS[1][3],
            "query_template": "{text}",
            "document_template": "{text}",
            "pooling": "mean",
            "dimensions": 384,
            "normalized": True,
            "metric": "cosine",
            "precision": "float32",
        },
        "max_tokens": 128,
        "overlap_tokens": 16,
        "output_name": "last_hidden_state",
        "threads": 1,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new private artifact directory")
    parser.add_argument("--accept-license", required=True, choices=["Apache-2.0"])
    args = parser.parse_args()
    try:
        if not hasattr(signal, "setitimer") or not hasattr(os, "O_NOFOLLOW"):
            raise PreparationError("PREPARATION_PLATFORM_UNSUPPORTED")
        # Resolve the existing parent, while preserving no-overwrite semantics for
        # the final directory component, including dangling symlinks.
        directory = args.output.parent.resolve(strict=True) / args.output.name
        os.mkdir(directory, 0o700)
        parent_fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), RestrictedRedirect()
            )
            for artifact in ARTIFACTS:
                fetch(opener, directory_fd, artifact)
            data = (json.dumps(manifest(directory), indent=2) + "\n").encode()
            promote(directory_fd, "encoder.json", lambda stream: stream.write(data))
        finally:
            os.close(directory_fd)
        print(
            json.dumps(
                {
                    "profile": "minilm-multilingual",
                    "revision": REVISION,
                    "verified_bytes": sum(item[2] for item in ARTIFACTS),
                    "manifest_sha256": hashlib.sha256(data).hexdigest(),
                    "inference_compatibility_verified": False,
                    "activated": False,
                }
            )
        )
        return 0
    except PreparationError as exc:
        print(str(exc), file=sys.stderr)
    except FileExistsError:
        print("PREPARATION_DESTINATION_EXISTS", file=sys.stderr)
    except (TimeoutError, urllib.error.URLError):
        print("DOWNLOAD_UNAVAILABLE", file=sys.stderr)
    except (OSError, ValueError):
        print("PREPARATION_FAILED", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
