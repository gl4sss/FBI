"""Persistent task state with process-safe advisory file locks."""

import fcntl
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def job_key(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


class FileLockLease:
    def __init__(self, stream):
        self.stream = stream
        self.locked = True

    def release(self) -> None:
        if self.locked:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.locked = False

    def __bool__(self) -> bool:
        return self.locked


@contextmanager
def file_lock(directory: Path, key: str, *, blocking: bool = False):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{job_key(key)}.lock"
    stream = path.open("a+b")
    try:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(stream.fileno(), flags)
        except BlockingIOError:
            yield False
            return
        lease = FileLockLease(stream)
        try:
            yield lease
        finally:
            lease.release()
    finally:
        stream.close()


class StateStore:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.database = self.directory / "jobs.sqlite3"
        self.locks = self.directory / "locks"
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS jobs (
                kind TEXT NOT NULL, key TEXT NOT NULL, status TEXT NOT NULL,
                payload TEXT NOT NULL, result TEXT, attempts INTEGER NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL, PRIMARY KEY (kind, key))""")

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=30)
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def enqueue(self, kind: str, key: str, payload: dict) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO jobs(kind,key,status,payload,updated_at) "
                "VALUES(?,?,?,?,?)",
                (kind, key, "pending", json.dumps(payload, ensure_ascii=False), time.time()),
            )

    def start(self, kind: str, key: str, payload: dict) -> None:
        """Start a stage already protected by a broader resource lock."""
        self.enqueue(kind, key, payload)
        with self._connect() as connection:
            connection.execute(
                "UPDATE jobs SET status='running',attempts=attempts+1,updated_at=? "
                "WHERE kind=? AND key=?", (time.time(), kind, key)
            )

    def get(self, kind: str, key: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status,payload,result,attempts,updated_at FROM jobs WHERE kind=? AND key=?",
                (kind, key),
            ).fetchone()
        if row is None:
            return None
        return {"kind": kind, "key": key, "status": row[0],
                "payload": json.loads(row[1]),
                "result": json.loads(row[2]) if row[2] else None,
                "attempts": row[3], "updated_at": row[4]}

    def list_jobs(self, kind: str | None = None) -> list[dict]:
        with self._connect() as connection:
            if kind is None:
                rows = connection.execute("SELECT kind,key FROM jobs ORDER BY updated_at,key").fetchall()
            else:
                rows = connection.execute(
                    "SELECT kind,key FROM jobs WHERE kind=? ORDER BY updated_at,key", (kind,)
                ).fetchall()
        return [self.get(row[0], row[1]) for row in rows]

    @contextmanager
    def claim(self, kind: str, key: str, payload: dict):
        self.enqueue(kind, key, payload)
        with file_lock(self.locks, f"{kind}:{key}") as locked:
            if not locked:
                yield None
                return
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT status,attempts FROM jobs WHERE kind=? AND key=?", (kind, key)
                ).fetchone()
                skip = row[0] == "complete"
                if not skip:
                    connection.execute(
                        "UPDATE jobs SET status='running',attempts=attempts+1,updated_at=? "
                        "WHERE kind=? AND key=?", (time.time(), kind, key)
                    )
            if skip:
                yield None
                return
            try:
                yield self
            except BaseException as exc:
                self.finish(kind, key, "failed", {"error": str(exc)})
                raise
            else:
                if self.get(kind, key)["status"] == "running":
                    self.finish(kind, key, "failed", {"error": "job ended without a result"})

    def finish(self, kind: str, key: str, status: str, result: dict) -> None:
        if status not in {"complete", "failed"}:
            raise ValueError(f"Invalid final status: {status}")
        with self._connect() as connection:
            connection.execute(
                "UPDATE jobs SET status=?,result=?,updated_at=? WHERE kind=? AND key=?",
                (status, json.dumps(result, ensure_ascii=False), time.time(), kind, key),
            )

    def summary(self) -> dict:
        counts = {}
        with self._connect() as connection:
            for kind, status, count in connection.execute(
                "SELECT kind,status,COUNT(*) FROM jobs GROUP BY kind,status"
            ):
                counts.setdefault(kind, {})[status] = count
        return counts
