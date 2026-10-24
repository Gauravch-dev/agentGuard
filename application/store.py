"""SQLite prototype store. HMAC chain detects edits, not host compromise/rollback."""

import hashlib
import hmac
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from application.models import now


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Store:
    def __init__(self, path: Path, key: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.key = key.encode()
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS task_contracts (
          task_id TEXT, version INTEGER, body TEXT NOT NULL, signature TEXT NOT NULL,
          state TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT, ended_at TEXT,
          PRIMARY KEY(task_id, version));
        CREATE TABLE IF NOT EXISTS evidence (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
          identity TEXT NOT NULL, task_id TEXT NOT NULL, body TEXT NOT NULL,
          received_at TEXT NOT NULL, previous_hash TEXT NOT NULL, digest TEXT NOT NULL,
          UNIQUE(kind, identity));
        CREATE TRIGGER IF NOT EXISTS immutable_evidence_update BEFORE UPDATE ON evidence
          BEGIN SELECT RAISE(ABORT, 'append-only evidence'); END;
        CREATE TRIGGER IF NOT EXISTS immutable_evidence_delete BEFORE DELETE ON evidence
          BEGIN SELECT RAISE(ABORT, 'append-only evidence'); END;
        CREATE TRIGGER IF NOT EXISTS immutable_contract BEFORE UPDATE OF body,signature ON task_contracts
          BEGIN SELECT RAISE(ABORT, 'immutable approved contract'); END;
        """)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def sign(self, value: Any) -> str:
        return hmac.new(self.key, canonical(value).encode(), hashlib.sha256).hexdigest()

    def _append(self, kind: str, identity: str, task_id: str, body: dict) -> bool:
        encoded = canonical(body)
        previous = self.db.execute(
            "SELECT digest FROM evidence ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        prior_hash = previous[0] if previous else "0" * 64
        received = now().isoformat()
        digest = self.sign([kind, identity, task_id, encoded, received, prior_hash])
        existing = self.db.execute(
            "SELECT body FROM evidence WHERE kind=? AND identity=?", (kind, identity)
        ).fetchone()
        if existing:
            if existing[0] != encoded:
                raise ValueError("conflicting duplicate evidence")
            return False
        self.db.execute(
            "INSERT INTO evidence(kind,identity,task_id,body,received_at,previous_hash,digest) VALUES(?,?,?,?,?,?,?)",
            (kind, identity, task_id, encoded, received, prior_hash, digest),
        )
        return True

    def append(self, kind: str, identity: str, task_id: str, body: dict) -> bool:
        if not self.verify_chain():
            raise ValueError("Evidence integrity check failed")
        with self.transaction():
            return self._append(kind, identity, task_id, body)

    def evidence(self, task_id: str, kind: str | None = None) -> list[dict]:
        with self.lock:
            query = "SELECT * FROM evidence WHERE task_id=?"
            args: tuple = (task_id,)
            if kind:
                query += " AND kind=?"
                args += (kind,)
            rows = self.db.execute(query + " ORDER BY sequence", args).fetchall()
            return [dict(row) | {"body": json.loads(row["body"])} for row in rows]

    def verify_chain(self) -> bool:
        with self.lock:
            previous = "0" * 64
            for row in self.db.execute("SELECT * FROM evidence ORDER BY sequence"):
                expected = self.sign(
                    [
                        row["kind"],
                        row["identity"],
                        row["task_id"],
                        row["body"],
                        row["received_at"],
                        previous,
                    ]
                )
                if row["previous_hash"] != previous or not hmac.compare_digest(
                    expected, row["digest"]
                ):
                    return False
                previous = row["digest"]
            return True
