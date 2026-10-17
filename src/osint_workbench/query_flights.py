"""Instance-scoped in-flight query sharing; no completed-result cache."""

import math
import os
import threading
from dataclasses import dataclass, field

from .errors import WorkbenchError


@dataclass
class _Flight:
    ready: threading.Event = field(default_factory=threading.Event)
    vector: tuple | None = None
    error: str = "ENCODER_UNAVAILABLE"


class QueryFlights:
    def __init__(self, *, max_owners=8, max_waiters=32, wait_seconds=45.0):
        if (
            type(max_owners) is not int
            or not 1 <= max_owners <= 64
            or type(max_waiters) is not int
            or not 1 <= max_waiters <= 256
            or type(wait_seconds) not in (int, float)
            or not math.isfinite(wait_seconds)
            or not 0 < wait_seconds <= 60
        ):
            raise ValueError("INVALID_QUERY_FLIGHT_LIMITS")
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._flights = {}
        self._waiters = 0
        self._max_owners = max_owners
        self._max_waiters = max_waiters
        self._wait_seconds = wait_seconds

    def run(self, key: bytes, compute):
        # Never touch a possibly inherited locked mutex after fork.
        if os.getpid() != self._pid:
            raise WorkbenchError("ENCODER_INSTANCE_FORKED")
        with self._lock:
            flight = self._flights.get(key)
            owner = flight is None
            if owner:
                if len(self._flights) >= self._max_owners:
                    raise WorkbenchError("ENCODER_COALESCING_BUSY")
                flight = _Flight()
                self._flights[key] = flight
            else:
                if self._waiters >= self._max_waiters:
                    raise WorkbenchError("ENCODER_COALESCING_BUSY")
                self._waiters += 1
        if not owner:
            try:
                if not flight.ready.wait(self._wait_seconds):
                    raise WorkbenchError("ENCODER_WAIT_TIMEOUT")
                if flight.vector is None:
                    raise WorkbenchError(flight.error)
                return list(flight.vector)
            finally:
                with self._lock:
                    self._waiters -= 1
        try:
            flight.vector = tuple(compute())
            return list(flight.vector)
        except WorkbenchError as exc:
            flight.error = exc.code
            raise
        finally:
            # BaseException also wakes waiters. Retain no traceback, query text,
            # completed cache entry, or model result after participants release it.
            with self._lock:
                del self._flights[key]
                flight.ready.set()
