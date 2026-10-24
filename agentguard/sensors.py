"""Normalize genuine externally captured Tetragon process events conservatively."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .schema import canonical, event, parse_time


@dataclass(frozen=True)
class Workload:
    container_id: str
    cgroup_id: str
    task_id: str
    contract_version: int
    capsule_id: str
    host_id: str
    started_at: str
    ended_at: str | None = None


class MappingError(ValueError):
    pass


class TetragonNormalizer:
    """Called only by a trusted host-side collector, never an agent-facing API.

    Raw transport authenticity and live health are NOT established by parsing JSON.
    This adapter is limited to process_exec/process_exit. Unsupported records remain
    unsupported, rather than inventing fields for kprobe or packet telemetry.
    """

    def __init__(self, sensor_id, workloads):
        self.sensor_id = sensor_id
        self.workloads = list(workloads)

    def normalize(self, raw, raw_reference):
        kind = "process_exec" if "process_exec" in raw else "process_exit" if "process_exit" in raw else None
        if kind is None:
            raise MappingError("unsupported Tetragon event type; retain raw record")
        body = raw[kind]
        process = body.get("process", {})
        docker_id = process.get("docker")
        observed = raw.get("time")
        start = process.get("start_time")
        if not isinstance(docker_id, str) or len(docker_id) < 12 or not observed or not start:
            raise MappingError("missing container or process-start identity; emit attribution gap")
        try:
            observed_time, start_time = parse_time(observed), parse_time(start)
        except ValueError as exc:
            raise MappingError("invalid source timestamp") from exc
        matches = [w for w in self.workloads if w.container_id.startswith(docker_id)
                   and start_time >= parse_time(w.started_at)
                   and observed_time >= start_time
                   and (w.ended_at is None or observed_time <= parse_time(w.ended_at))]
        if len(matches) != 1:
            raise MappingError("ambiguous, expired or unknown workload identity")
        w = matches[0]
        pid = process.get("pid")
        if type(pid) is not int or pid <= 0:
            pid = None
        # Do not include argument contents: they can carry credentials or payroll.
        binary = process.get("binary")
        if not isinstance(binary, str) or not binary:
            binary = None
        identity = hashlib.sha256((self.sensor_id + "\0" + canonical(raw)).encode()).hexdigest()
        return event(
            task_id=w.task_id, contract_version=w.contract_version, capsule_id=w.capsule_id,
            host_id=w.host_id, source="host_sensor", event_type=kind,
            operation="execute" if kind == "process_exec" else "exit", resource=binary,
            effect="observed", coverage="partial", event_id=identity, observed_at=observed,
            process_identity={"pid": pid, "start_time": start, "cgroup_id": w.cgroup_id},
            evidence_reference=raw_reference,
            details={"sensor_id": self.sensor_id, "coverage_scope": "captured process event only",
                     "attribution_basis": "trusted container/cgroup lifecycle map + sensor docker ID + process start",
                     "parent_exec_id": body.get("parent", {}).get("exec_id")},
        )
