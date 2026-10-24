"""Trusted local state. Never mount this database or its key into an agent."""

from __future__ import annotations

import hashlib
import hmac
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import sqlite3

from .schema import canonical, strict_json, timestamp, validate_event


class IntegrityError(ValueError):
    pass


def local_secret(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    key = path.read_bytes()
    if len(key) != 32:
        raise IntegrityError("invalid local secret file")
    return key


class Store:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key = local_secret(self.root / "authority.key")
        self.path = self.root / "agentguard.sqlite3"
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS contracts (
                    task_id TEXT NOT NULL, version INTEGER NOT NULL, body TEXT NOT NULL,
                    signature TEXT NOT NULL, created_at TEXT NOT NULL,
                    PRIMARY KEY(task_id, version));
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,
                    event_id TEXT NOT NULL, task_id TEXT NOT NULL, capsule_id TEXT NOT NULL,
                    body TEXT NOT NULL, previous_hash TEXT NOT NULL, chain_hash TEXT NOT NULL,
                    UNIQUE(source, event_id));
                CREATE TABLE IF NOT EXISTS runs (
                    capsule_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, version INTEGER NOT NULL,
                    mode TEXT NOT NULL, outcome TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reports (
                    capsule_id TEXT PRIMARY KEY, body TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS immutable_contract_update BEFORE UPDATE ON contracts
                    BEGIN SELECT RAISE(ABORT, 'immutable contract'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_contract_delete BEFORE DELETE ON contracts
                    BEGIN SELECT RAISE(ABORT, 'immutable contract'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_event_update BEFORE UPDATE ON events
                    BEGIN SELECT RAISE(ABORT, 'append-only evidence'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_event_delete BEFORE DELETE ON events
                    BEGIN SELECT RAISE(ABORT, 'append-only evidence'); END;
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def sign(self, domain: str, body: str) -> str:
        return hmac.new(self.key, (domain + "\0" + body).encode(), hashlib.sha256).hexdigest()

    def append(self, value: dict) -> bool:
        value = validate_event(value)
        body = canonical(value)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT body FROM events WHERE source=? AND event_id=?", (value["source"], value["event_id"])).fetchone()
            if existing:
                # Receipt times can differ on retry, but conflicting observations cannot.
                old, new = strict_json(existing["body"]), dict(value)
                old.pop("received_at")
                new.pop("received_at")
                if canonical(old) != canonical(new):
                    raise IntegrityError("conflicting duplicate event")
                return False
            last = db.execute("SELECT chain_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            previous = last["chain_hash"] if last else "0" * 64
            digest = self.sign("event", previous + body)
            db.execute("INSERT INTO events(source,event_id,task_id,capsule_id,body,previous_hash,chain_hash) VALUES(?,?,?,?,?,?,?)",
                       (value["source"], value["event_id"], value["task_id"], value["capsule_id"], body, previous, digest))
        return True

    def verify(self) -> dict:
        previous, count = "0" * 64, 0
        with self.connect() as db:
            for row in db.execute("SELECT * FROM events ORDER BY seq"):
                if row["previous_hash"] != previous or not hmac.compare_digest(row["chain_hash"], self.sign("event", previous + row["body"])):
                    raise IntegrityError(f"evidence integrity failure at sequence {row['seq']}")
                value = validate_event(strict_json(row["body"]))
                if any(row[column] != value[column] for column in ("source", "event_id", "task_id", "capsule_id")):
                    raise IntegrityError("evidence index differs from signed body")
                previous, count = row["chain_hash"], count + 1
        return {"verified_events": count, "head": previous, "limitation": "tail truncation requires an externally anchored head to detect"}

    def events(self, task_id=None, capsule_id=None):
        query, args = "SELECT body FROM events", []
        clauses = []
        for name, value in (("task_id", task_id), ("capsule_id", capsule_id)):
            if value is not None:
                clauses.append(name + "=?")
                args.append(value)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        with self.connect() as db:
            return [strict_json(row["body"]) for row in db.execute(query + " ORDER BY seq", args)]

    def create_run(self, capsule_id, contract, mode):
        with self.connect() as db:
            db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?)", (capsule_id, contract["task_id"], contract["contract_version"], mode, "running", timestamp()))

    def finish_run(self, capsule_id, outcome):
        if outcome not in {"completed", "failed", "interrupted"}:
            raise ValueError("invalid business outcome")
        with self.connect() as db:
            db.execute("UPDATE runs SET outcome=? WHERE capsule_id=?", (outcome, capsule_id))

    def runs(self, task_id=None):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM runs WHERE task_id=? ORDER BY created_at DESC", (task_id,)) if task_id else db.execute("SELECT * FROM runs ORDER BY created_at DESC")
            return [dict(row) for row in rows]

    def save_report(self, capsule_id, report):
        with self.connect() as db:
            db.execute("INSERT INTO reports VALUES(?,?,?)", (capsule_id, canonical(report), timestamp()))

    def report(self, capsule_id):
        with self.connect() as db:
            row = db.execute("SELECT body FROM reports WHERE capsule_id=?", (capsule_id,)).fetchone()
            return strict_json(row["body"]) if row else None
