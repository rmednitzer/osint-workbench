"""Bounded JSON HTTP exchange shared by acquisition and explicit token issuance."""

import httpcore

from . import fetch
from .errors import SourceHTTPError, WorkbenchError


def request_json(url, headers, deadline, *, method="GET", content=None, maximum=None):
    maximum = fetch.MAX_BYTES if maximum is None else maximum
    try:
        fetch._remaining(deadline)
        with httpcore.ConnectionPool(
            network_backend=fetch._PublicBackend(deadline),
            max_connections=1,
            max_keepalive_connections=0,
        ) as pool:
            with pool.stream(
                method,
                url,
                headers=headers,
                content=content,
                extensions={
                    "timeout": {k: fetch._remaining(deadline) for k in ("connect", "read", "write")}
                },
            ) as response:
                if response.status in {301, 302, 303, 307, 308}:
                    raise WorkbenchError("API_REDIRECT_REFUSED")
                if response.status in {401, 403}:
                    raise WorkbenchError(
                        "API_AUTHENTICATION_FAILED"
                        if response.status == 401
                        else "API_ENTITLEMENT_DENIED"
                    )
                if response.status in {429, 503}:
                    hint = fetch._single_header(
                        response.headers, b"retry-after", "INVALID_RETRY_AFTER"
                    )
                    seconds, when = (
                        fetch.parse_retry_after(hint) if hint is not None else (None, None)
                    )
                    raise SourceHTTPError(retry_after_seconds=seconds, retry_after_at=when)
                if response.status != 200:
                    raise WorkbenchError("API_HTTP_ERROR")
                mime = fetch._single_header(
                    response.headers, b"content-type", "API_MEDIA_TYPE_INVALID"
                )
                if mime is None or mime.split(b";", 1)[0].strip().lower() != b"application/json":
                    raise WorkbenchError("API_MEDIA_TYPE_INVALID")
                encoding = fetch._single_header(
                    response.headers, b"content-encoding", "UNSUPPORTED_CONTENT_ENCODING"
                )
                if encoding is not None and encoding.lower() != b"identity":
                    raise WorkbenchError("UNSUPPORTED_CONTENT_ENCODING")
                body = bytearray()
                for chunk in response.iter_stream():
                    fetch._remaining(deadline)
                    if len(body) + len(chunk) > maximum:
                        raise WorkbenchError("SOURCE_TOO_LARGE")
                    body.extend(chunk)
                return bytes(body)
    except WorkbenchError:
        raise
    except (
        httpcore.TimeoutException,
        httpcore.NetworkError,
        httpcore.ProtocolError,
        httpcore.ProxyError,
        httpcore.UnsupportedProtocol,
        OSError,
        UnicodeError,
        EOFError,
    ):
        raise WorkbenchError("API_UNAVAILABLE") from None
