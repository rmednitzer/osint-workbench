from datetime import UTC, datetime, timedelta


class WorkbenchError(Exception):
    """Public error-code container; callers must supply fixed, secret-free codes."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class SourceHTTPError(WorkbenchError):
    """Sanitized retry metadata; exception args/repr contain only a fixed code."""

    def __init__(
        self,
        code: str = "SOURCE_HTTP_ERROR",
        *,
        retry_after_seconds: int | None = None,
        retry_after_at: datetime | None = None,
    ):
        if code not in {"SOURCE_HTTP_ERROR", "INVALID_RETRY_AFTER"}:
            raise ValueError("INVALID_HTTP_ERROR_CODE")
        if retry_after_seconds is not None and (
            type(retry_after_seconds) is not int or not 0 <= retry_after_seconds <= 604801
        ):
            raise ValueError("INVALID_RETRY_DELAY")
        if retry_after_at is not None and (
            not isinstance(retry_after_at, datetime) or retry_after_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("INVALID_RETRY_DATE")
        if retry_after_seconds is not None and retry_after_at is not None:
            raise ValueError("AMBIGUOUS_RETRY_HINT")
        self.retry_after_seconds = retry_after_seconds
        self.retry_after_at = retry_after_at.astimezone(UTC) if retry_after_at is not None else None
        super().__init__(code)
