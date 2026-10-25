"""Durable at-least-once sensor delivery with explicit discontinuity accounting.

The queue is transport infrastructure, not proof that a sensor observed every
required effect. No complete coverage can be produced by this module.
"""

import hashlib
import json
import math
import os
import sqlite3
import stat
import time
from pathlib import Path

import httpx


class ExportQueue:
    MAX_FRAME = 65536

    def __init__(self, directory: Path, sensor_id: str, *, api_port: int = 8000):
        if type(api_port) is not int or not 1 <= api_port <= 65535:
            raise ValueError("Valid local API port required")
        self.api_port = api_port
        self.directory, self.sensor_id = Path(directory), sensor_id
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise PermissionError("Private collector-owned queue directory required")
        database = self.directory / "export.sqlite3"
        descriptor = os.open(database, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(descriptor)
        os.close(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("Untrusted queue database")
        import fcntl

        self.lock = os.open(
            self.directory / "collector.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.lock)
            raise PermissionError("Another collector owns this queue") from None
        try:
            self.initialize(database, sensor_id)
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            os.close(self.lock)
            self.lock = None
            raise

    def initialize(self, database, sensor_id):
        self.db = sqlite3.connect(database)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        # Preserve evidence instead of pruning silently. At the 64 MiB SQLite
        # limit, writes fail and the source checkpoint cannot advance.
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        self.db.execute(f"PRAGMA max_page_count={64 * 1024 * 1024 // page_size}")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS frames (
                seq INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL,
                payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS gaps (seq INTEGER PRIMARY KEY, reason TEXT NOT NULL);
        """)
        if "endpoint" not in {row[1] for row in self.db.execute("PRAGMA table_info(frames)")}:
            self.db.execute(
                "ALTER TABLE frames ADD COLUMN endpoint TEXT NOT NULL DEFAULT 'member2'"
            )
            self.db.commit()
        previous = self._get("sensor_id")
        if previous is not None and previous != sensor_id:
            raise PermissionError("Queue belongs to another sensor")
        with self.db:
            self._set("sensor_id", sensor_id)

    def _get(self, key):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def _set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value)))

    def gap(self, reason):
        self.db.execute("INSERT INTO gaps(reason) VALUES (?)", (reason,))

    def enqueue(self, payload, *, endpoint="member2"):
        if endpoint not in {"member2", "events", "coverage"}:
            raise ValueError("Only fixed local sensor ingestion routes are supported")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        namespace = "" if endpoint == "member2" else endpoint + "\0"
        key = hashlib.sha256((self.sensor_id + "\0" + namespace + encoded).encode()).hexdigest()
        self.db.execute(
            "INSERT OR IGNORE INTO frames(event_key,payload,endpoint) VALUES (?,?,?)",
            (key, encoded, endpoint),
        )

    def tail(self, path: Path, normalize, *, max_frames=256, endpoint="member2"):
        """Checkpoint only durable frames; partial EOF waits, replacement records a gap.

        normalize receives an unmodified source line and its content-hash reference.
        A normalization failure is retained as a gap, never repaired into an event.
        One queue owns one source path; reuse for a different path is refused.
        """
        path = Path(path).absolute()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise PermissionError("Private collector-owned capture required")
            source = str(path)
            if self._get("path") not in {None, source}:
                raise PermissionError("Queue source path changed")
            identity = [info.st_dev, info.st_ino]
            old = self._get("identity")
            offset = self._get("offset") or 0
            with self.db:
                self._set("path", source)
                if old is None:
                    self.gap("SOURCE_START_WITHOUT_PRIOR_COVERAGE")
                elif identity != old or info.st_size < offset:
                    self.gap("SOURCE_ROTATED_OR_TRUNCATED")
                    offset = 0
                elif offset:
                    stream.seek(max(0, offset - 64))
                    if hashlib.sha256(stream.read(min(offset, 64))).hexdigest() != self._get(
                        "anchor"
                    ):
                        self.gap("CHECKPOINT_CONTENT_CHANGED")
                        offset = 0
                self._set("identity", identity)
                self._set("offset", offset)
            stream.seek(offset)
            accepted = 0
            for _ in range(max_frames):
                start = stream.tell()
                line = stream.readline(self.MAX_FRAME + 1)
                if not line:
                    break  # EOF says nothing about source health or complete coverage.
                if len(line) > self.MAX_FRAME:
                    with self.db:
                        self.gap("OVERSIZE_FRAME_SOURCE_HELD")
                    raise ValueError("Oversize sensor frame; source held for operator review")
                if not line.endswith(b"\n"):
                    break  # Never checkpoint half a source event.
                end = stream.tell()
                reference = "tetragon:" + hashlib.sha256(line).hexdigest()
                with self.db:
                    try:
                        payload = normalize(line, reference)
                        self.enqueue(payload, endpoint=endpoint)
                        accepted += 1
                    except (ValueError, KeyError, TypeError, UnicodeError, PermissionError):
                        self.gap("NORMALIZATION_FAILED:" + reference)
                    stream.seek(max(0, end - 64))
                    anchor = hashlib.sha256(stream.read(min(end, 64))).hexdigest()
                    self._set("offset", end)
                    self._set("anchor", anchor)
                if end <= start:
                    raise RuntimeError("Source checkpoint failed to advance")
            return accepted

    def drain(self, token: str, *, client=None, max_frames=256, max_seconds=None):
        if len(token) < 32:
            raise ValueError("Registered sensor credential required")
        if max_seconds is not None and (
            isinstance(max_seconds, bool)
            or not isinstance(max_seconds, (int, float))
            or not math.isfinite(max_seconds)
            or not 0 < max_seconds <= 5
        ):
            raise ValueError("Bounded delivery time budget required")
        started = time.monotonic()
        owned = client is None
        client = client or httpx.Client(trust_env=False, follow_redirects=False, timeout=5)
        delivered = 0
        try:
            for seq, encoded, endpoint in self.db.execute(
                "SELECT seq,payload,endpoint FROM frames WHERE delivered=0 ORDER BY seq LIMIT ?",
                (max_frames,),
            ).fetchall():
                if max_seconds is not None and time.monotonic() - started >= max_seconds:
                    break  # Fair scheduling only; never discard or acknowledge pending frames.
                try:
                    routes = {
                        "member2": "/internal/v1/member2/events",
                        "events": "/internal/v1/events",
                        "coverage": "/internal/v1/coverage",
                    }
                    if endpoint not in routes:
                        raise ValueError("Invalid persisted delivery route")
                    response = client.post(
                        f"http://127.0.0.1:{self.api_port}" + routes[endpoint],
                        headers={"Authorization": "Bearer " + token},
                        json=json.loads(encoded),
                    )
                    response.raise_for_status()
                    if response.json().get("accepted") is not True:
                        raise ValueError("Source event not acknowledged")
                except (httpx.HTTPError, ValueError):
                    with self.db:
                        failures = self._get("export_failures") or 0
                        self._set("export_failures", failures + 1)
                        self.gap("EXPORT_UNACKNOWLEDGED")
                    break  # Reconnect on the next bounded pass; retain the exact frame.
                with self.db:
                    self.db.execute("UPDATE frames SET delivered=1 WHERE seq=?", (seq,))
                delivered += 1
        finally:
            if owned:
                client.close()
        return delivered

    def status(self):
        return {
            "pending": self.db.execute("SELECT count(*) FROM frames WHERE delivered=0").fetchone()[
                0
            ],
            "delivered": self.db.execute(
                "SELECT count(*) FROM frames WHERE delivered=1"
            ).fetchone()[0],
            "gaps": self.db.execute("SELECT count(*) FROM gaps").fetchone()[0],
            "export_failures": self._get("export_failures") or 0,
            "coverage_promoted": False,
        }

    def close(self):
        self.db.close()
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
