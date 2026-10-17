"""Database-clock leases and logical cancellation; no remote exactly-once claim."""

import json
import re
import uuid

from psycopg.types.json import Jsonb

from .database import Database
from .errors import WorkbenchError


def bounded_json(value: dict) -> Jsonb:
    try:
        if not isinstance(value, dict) or len(json.dumps(value, allow_nan=False).encode()) > 65536:
            raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise WorkbenchError("INVALID_JOB_PAYLOAD") from None
    return Jsonb(value)


def _uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise WorkbenchError("INVALID_JOB_IDENTITY") from None


def _seconds(value):
    if type(value) is not int or not 1 <= value <= 3600:
        raise WorkbenchError("INVALID_LEASE")
    return value


class Jobs:
    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def event(conn, row, event, code=None):
        conn.execute(
            "INSERT INTO ow.job_events(job_id,attempt,fence,event,code) VALUES (%s,%s,%s,%s,%s)",
            (row["job_id"], row["attempt"], row["fence"], event, code),
        )

    @staticmethod
    def locked(conn, job_id, fence):
        row = conn.execute(
            "SELECT * FROM ow.jobs WHERE job_id=%s FOR UPDATE", (_uuid(job_id),)
        ).fetchone()
        # Check the database clock after acquiring the lock, including lock wait time.
        live = (
            row
            and conn.execute(
                "SELECT %s > clock_timestamp() AS live", (row["lease_until"],)
            ).fetchone()["live"]
        )
        if not row or row["status"] != "running" or row["fence"] != _uuid(fence) or not live:
            raise WorkbenchError("STALE_JOB_LEASE")
        return row

    def claim(self, *, kinds: list[str] | None = None, lease_seconds: int = 30):
        _seconds(lease_seconds)
        if kinds is not None and (
            not kinds or len(kinds) > 32 or any(not isinstance(k, str) or not k for k in kinds)
        ):
            raise WorkbenchError("INVALID_JOB_KINDS")
        with self.database.connect() as conn:
            # Reap a bounded number of exhausted leases, then leave the rest for a later poll.
            for _ in range(64):
                row = conn.execute(
                    """SELECT * FROM ow.jobs WHERE
                    ((status='ready' AND available_at<=clock_timestamp()) OR
                     (status='running' AND lease_until<=clock_timestamp()))
                    AND (%s::text[] IS NULL OR kind=ANY(%s::text[]))
                    ORDER BY available_at,created_at,job_id FOR UPDATE SKIP LOCKED LIMIT 1""",
                    (kinds, kinds),
                ).fetchone()
                if row is None:
                    return None
                if row["status"] == "running":
                    self.event(conn, row, "expired", "LEASE_EXPIRED")
                if row["attempt"] >= row["max_attempts"]:
                    conn.execute(
                        """UPDATE ow.jobs SET status='failed',last_error='ATTEMPTS_EXHAUSTED',
                        lease_until=NULL,fence=NULL,updated_at=clock_timestamp() WHERE job_id=%s""",
                        (row["job_id"],),
                    )
                    self.event(conn, row, "failed", "ATTEMPTS_EXHAUSTED")
                    continue
                claimed = conn.execute(
                    """UPDATE ow.jobs SET status='running',attempt=attempt+1,fence=%s,
                    lease_until=clock_timestamp()+make_interval(secs=>%s),
                    updated_at=clock_timestamp() WHERE job_id=%s RETURNING *""",
                    (uuid.uuid4(), lease_seconds, row["job_id"]),
                ).fetchone()
                self.event(conn, claimed, "claimed")
                return claimed
        return None

    def finish(self, job_id, fence, result):
        result = bounded_json(result)
        with self.database.connect() as conn:
            row = self.locked(conn, job_id, fence)
            self.finish_locked(conn, row, result)

    def finish_locked(self, conn, row, result):
        accepted = conn.execute(
            """UPDATE ow.jobs SET status='succeeded',result=%s,lease_until=NULL,
            updated_at=clock_timestamp(),last_error=NULL WHERE job_id=%s AND status='running'
            AND fence=%s AND lease_until>clock_timestamp() RETURNING job_id""",
            (result, row["job_id"], row["fence"]),
        ).fetchone()
        if not accepted:
            raise WorkbenchError("STALE_JOB_LEASE")
        self.event(conn, row, "succeeded")

    def renew(self, job_id, fence, lease_seconds=30):
        _seconds(lease_seconds)
        with self.database.connect() as conn:
            row = conn.execute(
                """UPDATE ow.jobs SET lease_until=clock_timestamp()+make_interval(secs=>%s),
                updated_at=clock_timestamp() WHERE job_id=%s AND fence=%s
                AND status='running' AND lease_until>clock_timestamp() RETURNING lease_until""",
                (lease_seconds, _uuid(job_id), _uuid(fence)),
            ).fetchone()
            if not row:
                raise WorkbenchError("STALE_JOB_LEASE")
            return row["lease_until"]

    def fail(self, job_id, fence, code: str, *, retryable=True):
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
            raise WorkbenchError("INVALID_FAILURE_CODE")
        with self.database.connect() as conn:
            row = self.locked(conn, job_id, fence)
            retry = retryable and row["attempt"] < row["max_attempts"]
            delay = min(3600, 2 ** min(row["attempt"], 12))
            conn.execute(
                """UPDATE ow.jobs SET status=%s,last_error=%s,fence=NULL,lease_until=NULL,
                available_at=clock_timestamp()+make_interval(secs=>%s),
                updated_at=clock_timestamp() WHERE job_id=%s""",
                ("ready" if retry else "failed", code, delay, row["job_id"]),
            )
            self.event(conn, row, "retry" if retry else "failed", code)

    def cancel(self, job_id):
        with self.database.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ow.jobs WHERE job_id=%s FOR UPDATE", (_uuid(job_id),)
            ).fetchone()
            if row is None:
                raise WorkbenchError("JOB_NOT_FOUND")
            running = row["status"] == "running"
            if row["status"] in {"ready", "running"}:
                conn.execute(
                    """UPDATE ow.jobs SET status='cancelled',fence=NULL,lease_until=NULL,
                    updated_at=clock_timestamp() WHERE job_id=%s""",
                    (row["job_id"],),
                )
                self.event(conn, row, "cancelled")
                status = "cancelled"
            else:
                status = row["status"]
            return {
                "job_id": str(row["job_id"]),
                "status": status,
                "acceptance_revoked": status == "cancelled",
                "execution_stopped": False if running else None,
            }

    def inspect(self, job_id):
        with self.database.connect() as conn:
            row = conn.execute(
                """SELECT job_id,kind,status,attempt,max_attempts,available_at,
                lease_until,last_error,created_at,updated_at FROM ow.jobs WHERE job_id=%s""",
                (_uuid(job_id),),
            ).fetchone()
            if not row:
                raise WorkbenchError("JOB_NOT_FOUND")
            row["events"] = conn.execute(
                """SELECT event_id,attempt,event,code,recorded_at FROM ow.job_events
                WHERE job_id=%s ORDER BY event_id LIMIT 1000""",
                (_uuid(job_id),),
            ).fetchall()
            return row
