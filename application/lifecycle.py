"""Durable application orchestration; shared task/event schemas stay unchanged."""

from datetime import datetime, timedelta
from uuid import uuid4

from application.authority import Authority
from application.brokers import Broker
from application.config import Settings
from application.coverage import coverage_findings, release_coverage_ready
from application.models import Binding, Coverage, State, now
from application.staged_runtime import BASE_CONTROLS, StagedRuntimeAdapter
from application.store import Store

ACTIVE = {"launch_requested", "running"}


class TaskLifecycle:
    def __init__(
        self,
        store: Store,
        authority: Authority,
        broker: Broker,
        runtime: StagedRuntimeAdapter,
        settings: Settings,
    ) -> None:
        self.store, self.authority, self.broker = store, authority, broker
        self.runtime, self.settings = runtime, settings

    def binding(self, task_id: str) -> Binding | None:
        contract = self.authority.get(task_id)
        rows = self.store.evidence(task_id, "binding")
        return next(
            (
                Binding.model_validate(r["body"])
                for r in reversed(rows)
                if r["body"]["contract_version"] == contract.contract_version
            ),
            None,
        )

    def log(self, kind: str, task_id: str, body: dict) -> None:
        previous = self.store.evidence(task_id, kind)
        if previous and previous[-1]["body"] == body:
            return
        self.store.append(kind, uuid4().hex, task_id, body)

    def revoked(self, binding: Binding) -> bool:
        return any(
            r["body"]["capsule_id"] == binding.capsule_id
            for r in self.store.evidence(binding.task_id, "channel_revocation")
        )

    def revoke(self, binding: Binding, reason: str) -> None:
        if not self.revoked(binding):
            self.log(
                "channel_revocation",
                binding.task_id,
                {"capsule_id": binding.capsule_id, "reason": reason},
            )

    def coverage(self, binding: Binding) -> list[Coverage]:
        return [
            Coverage.model_validate(r["body"])
            for r in self.store.evidence(binding.task_id, "coverage")
        ]

    def monitored(self, binding: Binding) -> bool:
        checked = now()
        return release_coverage_ready(
            binding,
            self.coverage(binding),
            binding.process_start,
            max(binding.registered_at, checked - timedelta(seconds=5)),
            checked,
        )

    def gates(self, binding: Binding, *, review: bool = True) -> list[str]:
        reasons = []
        self.authority.get(binding.task_id, require_active=True)
        if self.revoked(binding):
            reasons.append("CHANNEL_REVOKED")
        if not self.monitored(binding):
            reasons.append("REQUIRED_SENSOR_COVERAGE_UNAVAILABLE")
        if review and not self.runtime.reviewed(binding):
            reasons.append("LIVE_PLATFORM_ADMISSION_REVIEW_PENDING")
        if not self.settings.local_model_enabled:
            reasons.append("LOCAL_MODEL_DISABLED")
        return reasons

    def prepare(self, task_id: str) -> dict:
        with self.store.lock:
            contract = self.authority.get(task_id, require_active=True)
            self.authority.transition(task_id, "launch_requested")
            binding = None
            try:
                result = self.runtime.launch(contract)
                self.log(
                    "readiness",
                    task_id,
                    result.model_dump(mode="json")
                    | {"contract_version": contract.contract_version},
                )
                binding = result.binding
                if (
                    binding is None
                    or binding.simulated
                    or result.simulated
                    or result.state != "launch_requested"
                    or not set(BASE_CONTROLS) <= set(result.controls)
                    or binding.task_id != task_id
                    or binding.contract_version != contract.contract_version
                    or binding.host_id not in {s.host_id for s in self.settings.sensors.values()}
                    or not now() - timedelta(seconds=30)
                    <= binding.process_start
                    <= binding.registered_at
                    <= now()
                ):
                    raise ValueError("Invalid staged runtime binding")
                # Unique capsule and channel identities must never be recycled.
                with self.store.lock:
                    prior = self.store.db.execute(
                        "SELECT body FROM evidence WHERE kind='binding'"
                    ).fetchall()
                if any(
                    Binding.model_validate_json(r[0]).capsule_id == binding.capsule_id
                    or Binding.model_validate_json(r[0]).channel_id == binding.channel_id
                    for r in prior
                ):
                    raise ValueError("Reused runtime identity")
                self.store.append(
                    "binding", binding.capsule_id, task_id, binding.model_dump(mode="json")
                )
                self.runtime.open_channel(binding, self.broker)
                self.log(
                    "staging", task_id, {"capsule_id": binding.capsule_id, "agent_admitted": False}
                )
                return {"state": "launch_requested", "binding": binding, "agent_admitted": False}
            except Exception:
                if binding is not None:
                    self.revoke(binding, "STAGING_FAILED")
                    try:
                        self.runtime.terminate(binding.capsule_id)
                    except Exception:
                        self.log("runtime_error", task_id, {"reason": "STAGING_CLEANUP_UNVERIFIED"})
                self.authority.transition(task_id, "failed")
                self.log("runtime_error", task_id, {"reason": "STAGING_FAILED"})
                raise

    def admit(self, task_id: str) -> dict:
        with self.store.lock:
            binding = self.binding(task_id)
            if binding is None or self.authority.record(task_id)["state"] != "launch_requested":
                raise ValueError("Task is not staged")
            reasons = self.gates(binding)
            if reasons:
                self.log(
                    "admission_hold",
                    task_id,
                    {"capsule_id": binding.capsule_id, "reasons": reasons},
                )
                return {"state": "launch_requested", "agent_admitted": False, "reasons": reasons}

            def check(value: dict) -> bool:
                # The controller holds its runtime-record lock here: review the
                # supplied trusted record, never recursively inspect/lock it.
                reviewer = self.runtime.admission_review
                return (
                    value["capsule_id"] == binding.capsule_id
                    and reviewer is not None
                    and reviewer(value)
                    and not self.gates(binding, review=False)
                )

            try:
                # The store lock prevents a broker request between the host marker
                # and durable running state. The controller rechecks live identity.
                self.runtime.admit(binding, check)
                self.authority.transition(task_id, "running")
                self.log(
                    "admission", task_id, {"capsule_id": binding.capsule_id, "agent_admitted": True}
                )
            except Exception:
                self.stop(task_id, "ADMISSION_FAILED")
                raise
            return {"state": "running", "binding": binding, "agent_admitted": True}

    def stop(self, task_id: str, reason: str = "OWNER_CANCELLED") -> dict:
        with self.store.lock:
            binding = self.binding(task_id)
            if binding is None:
                raise ValueError("No staged or running capsule")
            # Revocation survives a failed Docker call or application restart.
            self.revoke(binding, reason)
            execution_end = None
            try:
                self.runtime.record_for(binding)
                self.runtime.terminate(binding.capsule_id)
                inspected = self.runtime.inspect(binding.capsule_id)
                verified = inspected.descendants_exited and not inspected.simulated
                if verified:
                    execution_end = self.runtime.record_for(binding)["contained_at"]
                    if not binding.process_start <= datetime.fromisoformat(execution_end) <= now():
                        raise ValueError("Invalid verified runtime end")
            except Exception:
                verified = False
            self.log(
                "termination",
                task_id,
                {
                    "capsule_id": binding.capsule_id,
                    "descendants_exited": verified,
                    "channel_revoked": True,
                    "reason": reason,
                    "execution_end": execution_end if verified else None,
                },
            )
            if verified and self.authority.record(task_id)["state"] in ACTIVE:
                state: State = "failed" if reason == "ADMISSION_FAILED" else "interrupted"
                self.authority.transition(task_id, state)
            return {
                "state": self.authority.record(task_id)["state"],
                "descendants_exited": verified,
                "channel_revoked": True,
            }

    def sync(self, task_id: str) -> dict:
        with self.store.lock:
            row = self.authority.record(task_id)
            binding = self.binding(task_id)
            if binding is None or row["state"] not in ACTIVE:
                return {"state": row["state"]}
            finalizing = any(
                r["body"]["capsule_id"] == binding.capsule_id
                for r in self.store.evidence(task_id, "finalization")
            )
            if self.revoked(binding) and not finalizing:
                return self.stop(task_id, "REVOKED_CHANNEL_CLEANUP")
            contract = self.authority.get(task_id)
            if contract.expires_at <= now() or now() >= binding.process_start + timedelta(
                seconds=contract.limits.max_execution_seconds
            ):
                return self.stop(task_id, "EXECUTION_DEADLINE_REACHED")
            value = self.runtime.record_for(binding)
            inspected = self.runtime.inspect(binding.capsule_id)
            if inspected.descendants_exited:
                # A natural exit never establishes business success by itself.
                if not finalizing:
                    self.log("finalization", task_id, {"capsule_id": binding.capsule_id})
                    self.revoke(binding, "PROCESS_EXITED")
                    if self.runtime.sockets is not None:
                        self.runtime.sockets.close(binding.capsule_id)
                end = datetime.fromisoformat(value["contained_at"])
                if not binding.process_start <= end <= now():
                    raise ValueError("Invalid verified runtime end")
                reports = [
                    r
                    for r in self.store.evidence(task_id, "report")
                    if r["body"]["capsule_id"] == binding.capsule_id
                ]
                pending = coverage_findings(
                    binding, self.coverage(binding), binding.process_start, end
                )
                if (
                    inspected.state == "completed"
                    and reports
                    and pending
                    and now() < end + timedelta(seconds=30)
                ):
                    return {"state": row["state"], "phase": "awaiting_final_coverage"}
                success = inspected.state == "completed" and bool(reports) and not pending
                self.authority.transition(task_id, "completed" if success else "failed")
                self.log(
                    "task_result",
                    task_id,
                    {
                        "capsule_id": binding.capsule_id,
                        "descendants_exited": True,
                        "execution_end": end.isoformat(),
                        "state": "completed" if success else "failed",
                        "reason": "VERIFIED_REPORT_AND_EXIT"
                        if success
                        else "REPORT_OR_FINAL_COVERAGE_UNVERIFIED",
                    },
                )
            elif row["state"] == "running" and not self.monitored(binding):
                return self.stop(task_id, "LIVE_SENSOR_COVERAGE_LOST")
            return {"state": self.authority.record(task_id)["state"]}

    def active_tasks(self) -> list[str]:
        with self.store.lock:
            rows = self.store.db.execute(
                "SELECT task_id FROM task_contracts WHERE state IN ('launch_requested','running')"
            ).fetchall()
        return list(dict.fromkeys(r[0] for r in rows))

    def recover(self) -> None:
        self.runtime.controller.recover()
        # Restart never re-admits an old workload or restores an old channel.
        for task_id in self.active_tasks():
            if self.binding(task_id) is not None:
                self.stop(task_id, "APPLICATION_RESTART")
            else:
                self.authority.transition(task_id, "failed")

    def refresh(self) -> None:
        for task_id in self.active_tasks():
            try:
                self.sync(task_id)
            except Exception:
                # Inspection failure cannot leave a registered broker channel live.
                self.stop(task_id, "RUNTIME_INSPECTION_UNAVAILABLE")

    def shutdown(self) -> None:
        try:
            for task_id in self.active_tasks():
                self.stop(task_id, "APPLICATION_STOPPED")
        finally:
            self.runtime.shutdown()

    def status(self, task_id: str) -> dict:
        row = self.authority.record(task_id)
        binding = self.binding(task_id)
        phase, reasons = row["state"], []
        if binding is not None and row["state"] in ACTIVE:
            if any(
                r["body"]["capsule_id"] == binding.capsule_id
                for r in self.store.evidence(task_id, "finalization")
            ):
                phase, reasons = (
                    "awaiting_final_coverage",
                    ["Process exit verified; waiting for final monitoring evidence"],
                )
            elif self.revoked(binding):
                phase, reasons = (
                    "containment_unverified",
                    ["Channel revoked; process exit still needs verification"],
                )
            elif row["state"] == "launch_requested":
                phase = "waiting_for_admission"
                try:
                    reasons = self.gates(binding)
                except Exception:
                    reasons = ["Runtime inspection or active contract unavailable"]
            elif any(
                r["body"]["capsule_id"] == binding.capsule_id
                for r in self.store.evidence(task_id, "report")
            ):
                phase = "awaiting_verified_completion"
        return {
            "phase": phase,
            "reasons": reasons,
            "channel_revoked": self.revoked(binding) if binding else False,
            "agent_admitted": row["state"] == "running"
            and binding is not None
            and not self.revoked(binding),
        }
