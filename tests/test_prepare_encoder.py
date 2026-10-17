"""Exercise byte/hash/promotion policy without any model download or HTTP dispatch."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "prepare_encoder", Path(__file__).parents[1] / "scripts" / "prepare_encoder.py"
)
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)


class Response(io.BytesIO):
    status = 200
    headers = {}

    def geturl(self):
        return preparation.BASE_URL + "onnx/model.onnx"


class Opener:
    def __init__(self, data):
        self.data = data
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        assert timeout == 30
        assert not any(
            k.lower() in {"authorization", "proxy-authorization"} for k, _ in request.header_items()
        )
        return Response(self.data)


@pytest.mark.parametrize("failure", [None, "hash", "short", "oversize"])
def test_artifact_hash_byte_bounds_and_private_promotion(tmp_path, failure):
    data = b"independent synthetic artifact bytes"
    sha = hashlib.sha256(data).hexdigest()
    expected = len(data)
    if failure == "hash":
        sha = "0" * 64
    elif failure == "short":
        expected += 1
    elif failure == "oversize":
        expected -= 1
    opener = Opener(data)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if failure:
            with pytest.raises(preparation.PreparationError):
                preparation.fetch(
                    opener, directory, ("onnx/model.onnx", "model.onnx", expected, sha)
                )
            assert list(tmp_path.iterdir()) == []
        else:
            preparation.fetch(opener, directory, ("onnx/model.onnx", "model.onnx", expected, sha))
            target = tmp_path / "model.onnx"
            assert target.read_bytes() == data and target.stat().st_mode & 0o777 == 0o600
            with pytest.raises(FileExistsError):
                preparation.fetch(
                    opener, directory, ("onnx/model.onnx", "model.onnx", expected, sha)
                )
            assert target.read_bytes() == data
    finally:
        os.close(directory)
    assert len(opener.requests) >= 1


@pytest.mark.parametrize(
    "url",
    [
        "http:" + "//huggingface.co/file",
        "https://example.invalid/file",
        "https:" + "//127.0.0.1/file",
        "https:" + "//user:pass" + "@" + "huggingface.co/file",
        "https:" + "//huggingface.co:444/file",
        "https:" + "//huggingface.co/file#fragment",
    ],
)
def test_artifact_destination_policy_fails_closed(url):
    with pytest.raises(preparation.PreparationError):
        preparation.check_url(url)


def test_observed_public_artifact_cdn_is_explicitly_permitted():
    preparation.check_url("https:" + "//us.aws.cdn.hf.co/model")
