"""Native llama.cpp completion over an owner-checked Unix socket; no cloud route."""

import hashlib
import json
import os
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Literal

import httpcore
from jsonschema import Draft202012Validator
from pydantic import Field, field_validator

from .contracts import Digest, StrictModel
from .errors import WorkbenchError
from .fetch import _remaining, _Stream
from .local_encoder import admission
from .text import digest

TOKENIZATION_POLICY = "literal-source-prefix-specials-v1"


class GeneratorManifest(StrictModel):
    schema_version: Literal[1] = 1
    socket_path: str = Field(min_length=1, max_length=100, repr=False)
    peer_uid: int = Field(ge=0)
    runtime_binary_sha256: Digest
    runtime_source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    model_path: str = Field(min_length=1, repr=False)
    model_sha256: Digest
    model_alias: str = Field(min_length=1, max_length=100)
    context_tokens: int = Field(ge=128, le=131072)
    max_output_tokens: int = Field(default=1024, ge=16, le=4096)
    timeout_seconds: int = Field(default=45, ge=1, le=120)
    prompt_prefix: str = Field(default="", max_length=2000)
    prompt_suffix: str = Field(default="", max_length=2000)

    @field_validator("prompt_prefix", "prompt_suffix")
    @classmethod
    def safe_template(cls, value):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError:
            raise ValueError("invalid prompt template") from None
        if "\x00" in value:
            raise ValueError("invalid prompt template")
        return value

    def identity(self):
        return digest(
            json.dumps(
                {
                    **self.model_dump(exclude={"socket_path", "model_path", "peer_uid"}),
                    "tokenization_policy": TOKENIZATION_POLICY,
                },
                sort_keys=True,
            ).encode()
        )


def file_digest(path, maximum, *, kernel_link=False):
    flags = os.O_RDONLY | os.O_NONBLOCK | (0 if kernel_link else os.O_NOFOLLOW)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                raise WorkbenchError("INFERENCE_ARTIFACT_INVALID")
            value = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
            return value.hexdigest()
    except OSError:
        raise WorkbenchError("INFERENCE_ARTIFACT_UNAVAILABLE") from None


def _process_start(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def _check_prior_process(pid, start, peer_pid):
    if pid == peer_pid:
        # The identity-checked current peer has already reported its slot idle.
        return
    observed = _process_start(pid)
    if observed is not None:
        if observed == start:
            raise WorkbenchError("INFERENCE_PRIOR_PROCESS_ALIVE")
        return  # A different verified start token establishes PID reuse.
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    except OSError:
        pass
    # Missing /proc visibility is not evidence of termination. A live process,
    # denied liveness check, or other error keeps the uncertain reservation.
    raise WorkbenchError("INFERENCE_PRIOR_PROCESS_UNKNOWN")


class _UnixBackend(httpcore.SyncBackend):
    def __init__(self, manifest, deadline, peer):
        self.manifest, self.deadline = manifest, deadline
        self.peer = peer

    def connect_tcp(self, *args, **kwargs):
        raise WorkbenchError("INFERENCE_TCP_FORBIDDEN")

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        manifest = self.manifest
        info = os.lstat(path)
        if (
            path != manifest.socket_path
            or not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != manifest.peer_uid
            or info.st_mode & 0o007
        ):
            raise WorkbenchError("INFERENCE_SOCKET_UNSAFE")
        stream = super().connect_unix_socket(
            path, timeout=_remaining(self.deadline), socket_options=socket_options
        )
        try:
            sock = stream.get_extra_info("socket")
            pid, uid, _ = struct.unpack(
                "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if (
                uid != manifest.peer_uid
                or file_digest(f"/proc/{pid}/exe", 256 * 1024**2, kernel_link=True)
                != manifest.runtime_binary_sha256
            ):
                raise WorkbenchError("INFERENCE_PEER_MISMATCH")
            self.peer.update({"pid": pid, "start": _process_start(pid)})
            return _Stream(stream, self.deadline)
        except Exception:
            stream.close()
            raise


class LocalGenerator:
    def __init__(self, manifest: GeneratorManifest):
        self.manifest = manifest

    def _request(self, pool, path, body=None):
        data = json.dumps(body, allow_nan=False).encode() if body is not None else b""
        with pool.stream(
            "POST" if body is not None else "GET",
            "http://inference.invalid" + path,
            headers=[("Content-Type", "application/json"), ("Accept-Encoding", "identity")],
            content=data,
            extensions={
                "timeout": {"connect": 5, "read": self.manifest.timeout_seconds, "write": 5}
            },
        ) as response:
            if response.status != 200:
                raise WorkbenchError("INFERENCE_HTTP_FAILURE")
            headers = {k.lower(): v for k, v in response.headers}
            if headers.get(b"content-encoding", b"identity") != b"identity":
                raise WorkbenchError("INFERENCE_PROTOCOL_ERROR")
            content = bytearray()
            for block in response.iter_stream():
                if len(content) + len(block) > 1024 * 1024:
                    raise WorkbenchError("INFERENCE_RESULT_LIMIT")
                content.extend(block)
            return json.loads(content)

    def _pool(self):
        self._peer = {}
        return httpcore.ConnectionPool(
            uds=self.manifest.socket_path,
            network_backend=_UnixBackend(
                self.manifest, time.monotonic() + self.manifest.timeout_seconds, self._peer
            ),
            max_connections=1,
            max_keepalive_connections=1,
            retries=0,
        )

    def _probe(self, pool):
        props = self._request(pool, "/props")
        if (
            not isinstance(props, dict)
            or props.get("model_path") != self.manifest.model_path
            or props.get("total_slots") != 1
            or props.get("default_generation_settings", {}).get("n_ctx", 0)
            < self.manifest.context_tokens
        ):
            raise WorkbenchError("INFERENCE_CAPABILITY_MISMATCH")
        if file_digest(self.manifest.model_path, 32 * 1024**3) != self.manifest.model_sha256:
            raise WorkbenchError("MODEL_INTEGRITY_MISMATCH")

    def _prompt_tokens(self, pool, prompt):
        # Only operator-owned template segments may interpret model control tokens.
        # Submit IDs so completion cannot reparse hostile source text. Automatic
        # tokenizer specials must be a bounded prefix, not an EOS moved before data.
        manifest = self.manifest

        def tokenize(content, *, add_special, parse_special):
            result = self._request(
                pool,
                "/tokenize",
                {"content": content, "add_special": add_special, "parse_special": parse_special},
            )
            tokens = result.get("tokens") if isinstance(result, dict) else None
            if not isinstance(tokens, list) or any(
                type(token) is not int or not 0 <= token <= 2147483647 for token in tokens
            ):
                raise WorkbenchError("INFERENCE_PROTOCOL_ERROR")
            if len(tokens) + manifest.max_output_tokens > manifest.context_tokens:
                raise WorkbenchError("GENERATION_CONTEXT_EXCEEDED")
            return tokens

        source = tokenize(prompt, add_special=False, parse_special=False)
        if not source:
            raise WorkbenchError("INFERENCE_CAPABILITY_MISMATCH")
        automatic = tokenize(prompt, add_special=True, parse_special=False)
        added = len(automatic) - len(source)
        if not 0 <= added <= 8 or automatic[added:] != source:
            raise WorkbenchError("INFERENCE_CAPABILITY_MISMATCH")
        prefix = tokenize(manifest.prompt_prefix, add_special=False, parse_special=True)
        suffix = tokenize(manifest.prompt_suffix, add_special=False, parse_special=True)
        ids = automatic[:added] + prefix + source + suffix
        if len(ids) + manifest.max_output_tokens > manifest.context_tokens:
            raise WorkbenchError("GENERATION_CONTEXT_EXCEEDED")
        return ids

    def generate(self, prompt: str, schema: dict):
        if not isinstance(prompt, str) or not 1 <= len(prompt) <= 32000:
            raise WorkbenchError("INVALID_GENERATION_INPUT")
        # Only application-owned, bounded schemas enter this integration.
        Draft202012Validator.check_schema(schema)
        if len(json.dumps(schema)) > 32000:
            raise WorkbenchError("INVALID_GENERATION_SCHEMA")
        manifest = self.manifest
        try:
            GeneratorManifest.safe_template(manifest.prompt_prefix)
            GeneratorManifest.safe_template(manifest.prompt_suffix)
            prompt.encode("utf-8", errors="strict")
            if "\x00" in prompt:
                raise ValueError
        except (ValueError, UnicodeError):
            raise WorkbenchError("INVALID_GENERATION_INPUT") from None
        prompt_sha256 = digest(
            (manifest.prompt_prefix + prompt + manifest.prompt_suffix).encode("utf-8")
        )
        submitted = False
        with admission() as held, self._pool() as pool:
            try:
                self._probe(pool)
                ids = self._prompt_tokens(pool, prompt)
                receipt = held.create_marker(manifest.identity(), self._peer)
                submitted = True
                result = self._request(
                    pool,
                    "/completion",
                    {
                        "prompt": ids,
                        "stream": False,
                        "n_predict": manifest.max_output_tokens,
                        "temperature": 0,
                        "seed": 0,
                        "cache_prompt": False,
                        "json_schema": schema,
                    },
                )
                # A complete native response establishes request termination; it does not
                # validate the generated schema or assertions.
                if (
                    not isinstance(result, dict)
                    or result.get("model") != manifest.model_alias
                    or result.get("stop_type") not in {"eos", "word", "limit"}
                ):
                    raise WorkbenchError("INFERENCE_PROTOCOL_ERROR")
                held.remove_marker(receipt)
                submitted = False
                if result.get("truncated") is not False or result["stop_type"] == "limit":
                    raise WorkbenchError("GENERATION_INCOMPLETE")
                content = result.get("content")
                if not isinstance(content, str) or len(content) > 65536:
                    raise WorkbenchError("INVALID_MODEL_RESULT")
                try:
                    decoded = json.loads(content)
                    Draft202012Validator(schema).validate(decoded)
                except Exception:
                    raise WorkbenchError("INVALID_MODEL_RESULT") from None
                return {
                    "output": decoded,
                    "response_sha256": digest(content.encode()),
                    "prompt_sha256": prompt_sha256,
                    "generator_id": manifest.identity(),
                }
            except Exception as exc:
                if submitted:
                    raise WorkbenchError("INFERENCE_OUTCOME_UNKNOWN") from None
                if isinstance(exc, WorkbenchError):
                    raise
                raise WorkbenchError("INFERENCE_UNAVAILABLE") from None

    def reconcile(self):
        with admission(allow_uncertain=True) as held, self._pool() as pool:
            self._probe(pool)
            slots = self._request(pool, "/slots")
            if (
                not isinstance(slots, list)
                or len(slots) != 1
                or slots[0].get("is_processing") is not False
            ):
                raise WorkbenchError("INFERENCE_STILL_RUNNING")
            marker = held.read_marker()
            if marker is not None:
                receipt = marker.value
                if receipt["generator_id"] != self.manifest.identity():
                    raise WorkbenchError("INFERENCE_OWNER_MISMATCH")
                _check_prior_process(receipt["pid"], receipt["start"], self._peer.get("pid"))
                held.remove_marker(marker)
            return {"status": "idle", "generator_id": self.manifest.identity()}
