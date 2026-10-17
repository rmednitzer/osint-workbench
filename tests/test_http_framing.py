"""Real HTTP/1.1 protocol over an in-memory wire, without a private-address bypass."""

import h11
import httpcore
import pytest

from osint_workbench import fetch as acquisition
from osint_workbench.local_generation import GeneratorManifest, LocalGenerator


class Wire:
    def __init__(self, payload):
        self.server = h11.Connection(h11.SERVER)
        self.payload = payload
        self.response = None
        self.request = None
        self.body = bytearray()

    def write(self, buffer, timeout=None):
        if not buffer:
            return
        self.server.receive_data(buffer)
        while True:
            event = self.server.next_event()
            if event is h11.NEED_DATA:
                break
            if isinstance(event, h11.ConnectionClosed):
                break
            if isinstance(event, h11.Request):
                self.request = event
            elif isinstance(event, h11.Data):
                self.body.extend(event.data)
            elif isinstance(event, h11.EndOfMessage):
                self.response = (
                    self.server.send(
                        h11.Response(
                            status_code=200,
                            headers=[(b"Content-Length", str(len(self.payload)).encode())],
                        )
                    )
                    + self.server.send(h11.Data(data=self.payload))
                    + self.server.send(h11.EndOfMessage())
                )
                break

    def read(self, max_bytes, timeout=None):
        assert self.response is not None
        result = self.response[:max_bytes]
        self.response = self.response[max_bytes:]
        return result

    def close(self):
        pass

    def get_extra_info(self, info):
        return None


class Backend(httpcore.SyncBackend):
    def __init__(self, wire):
        self.wire = wire

    def connect_tcp(self, *args, **kwargs):
        return self.wire


def test_acquisition_adds_host_and_preserves_stream_bound(monkeypatch):
    wire = Wire(b"synthetic evidence")
    monkeypatch.setattr(acquisition, "_PublicBackend", lambda _: Backend(wire))
    assert acquisition.fetch("http://example.invalid/feed") == b"synthetic evidence"
    assert (b"host", b"example.invalid") in wire.request.headers
    assert wire.request.target == b"/feed"
    wire = Wire(b"over limit")
    monkeypatch.setattr(acquisition, "_PublicBackend", lambda _: Backend(wire))
    with pytest.raises(Exception, match="SOURCE_TOO_LARGE"):
        acquisition.fetch("http://example.invalid/feed", max_bytes=2)


def test_generation_adds_host_and_content_length_with_bounded_stream():
    wire = Wire(b'{"tokens":[1,2]}')
    generator = LocalGenerator(
        GeneratorManifest(
            socket_path="/synthetic/server.sock",
            peer_uid=0,
            runtime_binary_sha256="a" * 64,
            runtime_source_revision="b" * 40,
            model_path="/synthetic/model.gguf",
            model_sha256="c" * 64,
            model_alias="synthetic",
            context_tokens=4096,
            max_output_tokens=128,
        )
    )
    with httpcore.ConnectionPool(network_backend=Backend(wire)) as pool:
        assert generator._request(pool, "/tokenize", {"content": "synthetic"}) == {"tokens": [1, 2]}
    headers = dict(wire.request.headers)
    assert headers[b"host"] == b"inference.invalid"
    assert int(headers[b"content-length"]) == len(wire.body)
