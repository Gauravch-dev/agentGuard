import hmac
import json
from datetime import timedelta
from uuid import uuid4

from application.models import State, TaskContract, now
from application.store import Store, canonical

TRANSITIONS: dict[str, set[str]] = {
    "created": {"approved"},
    "approved": {"launch_requested"},
    "launch_requested": {"running", "failed", "interrupted"},
    "running": {"completed", "failed", "interrupted"},
    "completed": set(),
    "failed": set(),
    "interrupted": set(),
}


class Authority:
    def __init__(self, store: Store):
        self.store = store

    def create(self, approver: str, task_id: str | None = None, version: int = 1) -> TaskContract:
        if not self.store.verify_chain():
            raise ValueError("INVALID_CONTRACT")
        contract = TaskContract(
            task_id=task_id or f"FIN-{uuid4().hex}",
            contract_version=version,
            approved_by=approver,
            expires_at=now() + timedelta(hours=1),
        )
        body = contract.model_dump(mode="json")
        with self.store.transaction():
            self.store.db.execute(
                "INSERT INTO task_contracts(task_id,version,body,signature,state,created_at) VALUES(?,?,?,?,?,?)",
                (
                    contract.task_id,
                    version,
                    canonical(body),
                    self.store.sign(body),
                    "created",
                    now().isoformat(),
                ),
            )
            self.store._append(
                "lifecycle",
                uuid4().hex,
                contract.task_id,
                {"state": "created", "version": version, "approved_by": approver},
            )
        self.transition(contract.task_id, "approved")
        return contract

    def record(self, task_id: str) -> dict:
        with self.store.lock:
            row = self.store.db.execute(
                "SELECT * FROM task_contracts WHERE task_id=? ORDER BY version DESC LIMIT 1",
                (task_id,),
            ).fetchone()
        if not row:
            raise KeyError("task not found")
        return dict(row)

    def get(self, task_id: str, require_active: bool = False) -> TaskContract:
        if not self.store.verify_chain():
            raise ValueError("INVALID_CONTRACT")
        row = self.record(task_id)
        body = json.loads(row["body"])
        if not hmac.compare_digest(self.store.sign(body), row["signature"]):
            raise ValueError("INVALID_CONTRACT")
        contract = TaskContract.model_validate(body)
        if require_active and (
            contract.expires_at <= now()
            or row["state"] not in {"approved", "launch_requested", "running"}
        ):
            raise ValueError("expired or inactive contract")
        return contract

    def transition(self, task_id: str, state: State) -> None:
        with self.store.transaction():
            row = self.record(task_id)
            if state not in TRANSITIONS[row["state"]]:
                raise ValueError(f"invalid lifecycle transition {row['state']} -> {state}")
            started = now().isoformat() if state == "running" else row["started_at"]
            ended = now().isoformat() if state in {"completed", "failed", "interrupted"} else None
            self.store.db.execute(
                "UPDATE task_contracts SET state=?,started_at=?,ended_at=? WHERE task_id=? AND version=?",
                (state, started, ended, task_id, row["version"]),
            )
            self.store._append(
                "lifecycle", uuid4().hex, task_id, {"state": state, "version": row["version"]}
            )

    def revise(self, task_id: str, approver: str) -> TaskContract:
        row = self.record(task_id)
        if row["state"] not in {"completed", "failed", "interrupted"}:
            raise ValueError("active contracts cannot be revised")
        self.get(task_id)
        return self.create(approver, task_id, row["version"] + 1)
