from __future__ import annotations

import hmac
import sqlite3
from datetime import timedelta

from .schema import OPERATIONS, ValidationError, canonical, strict_json, timestamp, utcnow, validate_contract
from .store import IntegrityError, Store


class Authority:
    def __init__(self, store: Store, approver="local-project-owner"):
        self.store, self.approver = store, approver

    def approve(self, proposed: dict) -> dict:
        contract = validate_contract(proposed)
        if contract["approved_by"] != self.approver:
            raise ValidationError("approver must match the authenticated local authority")
        body = canonical(contract)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            latest = db.execute("SELECT MAX(version) FROM contracts WHERE task_id=?", (contract["task_id"],)).fetchone()[0]
            if contract["contract_version"] != (latest or 0) + 1:
                raise ValidationError("contract versions must increase by exactly one")
            try:
                db.execute("INSERT INTO contracts VALUES(?,?,?,?,?)", (contract["task_id"], contract["contract_version"], body, self.store.sign("contract", body), timestamp()))
            except sqlite3.IntegrityError as exc:
                raise ValidationError("contract version already exists") from exc
        return contract

    def load(self, task_id: str, version: int | None = None, *, check_expiry=True):
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM contracts WHERE task_id=? ORDER BY version DESC LIMIT 1", (task_id,)).fetchone() if version is None else db.execute("SELECT * FROM contracts WHERE task_id=? AND version=?", (task_id, version)).fetchone()
        if row is None:
            raise KeyError("task contract not found")
        if not hmac.compare_digest(row["signature"], self.store.sign("contract", row["body"])):
            raise IntegrityError("contract signature failed")
        contract = validate_contract(strict_json(row["body"]), check_expiry=check_expiry)
        if contract["task_id"] != row["task_id"] or contract["contract_version"] != row["version"]:
            raise IntegrityError("contract index differs from signed body")
        return contract

    def list(self):
        with self.store.connect() as db:
            keys = db.execute("SELECT task_id,MAX(version) AS version FROM contracts GROUP BY task_id ORDER BY task_id").fetchall()
        return [self.load(row["task_id"], row["version"], check_expiry=False) for row in keys]


def sample_contract(task_id="FIN-001", version=1):
    return {
        "schema_version": "1.0", "task_id": task_id, "contract_version": version,
        "approved_by": "local-project-owner", "agent_role": "finance-reporting",
        "objective": "Prepare department-wise totals from synthetic payroll",
        "allowed_operations": sorted(OPERATIONS), "allowed_data_classes": ["synthetic_payroll_aggregate"],
        "approved_output_destination": "internal_reports", "output_schema": "department_summary_v1",
        "direct_internet_allowed": False, "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
        "limits": {"max_execution_seconds": 180, "max_memory_mb": 768, "max_processes": 64},
    }
