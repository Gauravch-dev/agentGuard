from __future__ import annotations

from uuid import uuid4

from .authority import Authority, sample_contract
from .brokers import Binding, BrokerDenied, BrokerSession, request
from .reconcile import reconcile
from .schema import event
from .store import Store


class Workbench:
    def __init__(self, root):
        self.store = Store(root)
        self.authority = Authority(self.store)

    def seed(self):
        try:
            return self.authority.load("FIN-001")
        except (KeyError, ValueError):
            try:
                latest = self.authority.load("FIN-001", check_expiry=False)
                version = latest["contract_version"] + 1
            except KeyError:
                version = 1
            return self.authority.approve(sample_contract(version=version))

    def harness(self, task_id, *, include_denial=True):
        contract = self.authority.load(task_id)
        capsule_id = "harness-" + uuid4().hex
        self.store.create_run(capsule_id, contract, "policy-harness")
        binding = Binding(task_id, contract["contract_version"], capsule_id, "local-workbench", "policy-harness")
        session = BrokerSession(self.store, self.authority, binding)
        self.store.append(event(
            task_id=task_id, contract_version=contract["contract_version"], capsule_id=capsule_id,
            source="sensor_health", event_type="sensor_health", operation="coverage",
            coverage="unavailable", details={"execution_mode": "policy-harness", "reason": "No agent or independent host sensor is running in this policy harness", "lost_events": None},
        ))
        try:
            summary = session.request(request("data.get_department_totals", {}))["result"]
            if include_denial:
                try:
                    session.request(request("output.save_department_summary", {"employees": [{"name": "Synthetic Person", "salary": 42000}], "currency": "INR"}))
                except BrokerDenied:
                    pass
            session.request(request("output.save_department_summary", summary))
            self.store.finish_run(capsule_id, "completed")
        except Exception:
            self.store.finish_run(capsule_id, "failed")
            raise
        finally:
            session.revoke()
        return self.result(capsule_id)

    def result(self, capsule_id):
        run = next((row for row in self.store.runs() if row["capsule_id"] == capsule_id), None)
        if run is None:
            raise KeyError("run not found")
        contract = self.authority.load(run["task_id"], run["version"], check_expiry=False)
        self.store.verify()
        events = self.store.events(capsule_id=capsule_id)
        return {"run": run, "contract": contract, "report": self.store.report(capsule_id), "events": events,
                "assessment": reconcile(contract, events, outcome=run["outcome"], mode=run["mode"])}

    def snapshot(self):
        integrity = self.store.verify()
        return {"version": "0.1.0", "tasks": self.authority.list(), "runs": self.store.runs(),
                "integrity": integrity, "protected_execution_ready": False,
                "limitations": ["Live sensor coverage and protected broker/container integration are pending Linux validation.",
                                "Policy harness runs are trusted local tests; they do not establish OS isolation."]}
