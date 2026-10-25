"""Explicit adapters for Member 2 commit 198aea6515954130ed58ed21601a23be767596a0.

Parsing is not authentication. Protected execution remains gated by the actual
upstream preflight and incomplete live sensor/admission validation.
"""

from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Any

from pydantic import Field

from agentguard.platform import DockerLab, PlatformError, host_audit
from agentguard.schema import validate_contract, validate_event
from agentguard.sensors import MappingError, TetragonNormalizer, Workload
from agentguard.transport import PeerAuthorizer
from application.brokers import Broker, ChannelContext
from application.models import Binding, RuntimeResult, SecurityEvent, StrictModel, TaskContract

UPSTREAM_COMMIT = "198aea6515954130ed58ed21601a23be767596a0"  # pragma: allowlist secret


class Member2Transfer(StrictModel):
    wire_format: str = Field(pattern=r"^member2-normalized-1\.0$")
    event: dict


class Member2RuntimeAdapter:
    """Reuses the real upstream preflight and fixed isolation lab, never the harness."""

    def __init__(self, lab: Any = None, approved_image: str | None = None):
        self.lab = lab if lab is not None else DockerLab()
        self.approved_image = approved_image
        self.last_preflight: list[dict] = []

    def preflight(self) -> dict:
        self.last_preflight = [asdict(check) for check in self.lab.preflight(protected=True)]
        return {
            "upstream_commit": UPSTREAM_COMMIT,
            "checks": self.last_preflight,
            "protected_execution_ready": False,
            "reason": "Protected application admission and continuous sensor coverage are not yet verified",
        }

    def capabilities(self) -> dict:
        return {"audit": host_audit(), "preflight": self.preflight()}

    def launch(self, contract_ref: TaskContract) -> RuntimeResult:
        validate_contract(contract_ref.model_dump(mode="json"))
        result = self.preflight()
        failed = [c["name"] for c in result["checks"] if c["mandatory"] and c["status"] != "passed"]
        reason = "Member 2 preflight refused: " + ", ".join(failed) if failed else result["reason"]
        # Passing fixed Docker probes never promotes a protected agent to ready.
        return RuntimeResult(state="failed", readiness_passed=False, reason=reason)

    def inspect(self, capsule_id: str) -> RuntimeResult:
        return RuntimeResult(
            state="failed",
            readiness_passed=False,
            reason="No protected workload binding is registered; exit is unverified",
        )

    def terminate(self, capsule_id: str) -> RuntimeResult:
        return RuntimeResult(
            state="failed",
            readiness_passed=False,
            reason="Unknown protected capsule; no arbitrary Docker kill is permitted",
        )

    def observe(self) -> Iterator[SecurityEvent]:
        return iter(())

    def isolation_lab(self, contract: TaskContract) -> dict:
        if not self.approved_image:
            raise PlatformError(
                "Set an operator-reviewed local image ID; no image is pulled automatically"
            )
        return self.lab.isolation_lab(contract.model_dump(mode="json"), self.approved_image)


def translate_member2_event(value: dict, sensor_id: str) -> tuple[SecurityEvent, dict]:
    """Translate the upstream extension into the unchanged shared event plus metadata."""
    checked = validate_event(value)
    if checked["source"] != "host_sensor" or checked["event_type"] not in {
        "process_exec",
        "process_exit",
        "file_access",
        "connection_attempt",
    }:
        raise PermissionError(
            "Only supported Member 2 host observations are accepted by this bridge"
        )
    details = checked["details"]
    allowed = {
        "sensor_id",
        "coverage_scope",
        "attribution_basis",
        "parent_exec_id",
        "hook_policy",
        "kernel_return",
    }
    if details.get("sensor_id") != sensor_id or set(details) - allowed:
        raise PermissionError("Collector identity or metadata scope mismatch")
    if checked["event_type"] in {"file_access", "connection_attempt"} and (
        checked["coverage_status"] != "partial"
        or checked["policy_verdict"] != "unknown"
        or checked["effect_status"] not in {"attempted", "observed"}
        or not isinstance(details.get("hook_policy"), str)
        or type(details.get("kernel_return")) is not int
    ):
        raise PermissionError("Hook observation cannot certify enforcement or complete coverage")
    shared = {key: item for key, item in checked.items() if key not in {"received_at", "details"}}
    # Unsupported identifiers or fields are rejected, never truncated or guessed.
    event = SecurityEvent.model_validate(shared)
    metadata = {
        "wire_format": "member2-normalized-1.0",
        "upstream_commit": UPSTREAM_COMMIT,
        "collector_received_at": checked["received_at"],
        "details": details,
    }
    return event, metadata


def normalize_tetragon(
    raw: dict, reference: str, sensor_id: str, workloads: list[Workload]
) -> tuple[SecurityEvent, dict]:
    kinds = {"process_exec", "process_exit"} & raw.keys() if isinstance(raw, dict) else set()
    if len(kinds) != 1:
        raise MappingError("Exactly one supported process event is required")
    body = raw[next(iter(kinds))]
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("process"), dict)
        or ("parent" in body and not isinstance(body["parent"], dict))
    ):
        raise MappingError("Unsupported process/parent shape; retain raw capture and report a gap")
    value = TetragonNormalizer(sensor_id, workloads).normalize(raw, reference)
    return translate_member2_event(value, sensor_id)


class Member2ChannelAuthorizer:
    """Real SO_PEERCRED/cgroup checks, then host-recorded birth/inode and broker revocation."""

    def __init__(
        self,
        broker: Broker,
        binding: Binding,
        cgroup_path: str,
        minimum_start_ticks: int,
        cgroup_inode: int,
        *,
        expected_uid: int = 65532,
        proc_root: Path = Path("/proc"),
        cgroup_root: Path = Path("/sys/fs/cgroup"),
    ):
        if minimum_start_ticks < 1 or cgroup_inode < 1 or ".." in Path(cgroup_path).parts:
            raise ValueError("Trusted process birth and cgroup inode are required")
        self.broker, self.binding = broker, binding
        self.minimum_start_ticks, self.inode = minimum_start_ticks, cgroup_inode
        root = cgroup_root.resolve()
        self.directory = (root / cgroup_path.lstrip("/")).resolve()
        if self.directory == root or not self.directory.is_relative_to(root):
            raise ValueError("Unsafe cgroup path")
        self.peer = PeerAuthorizer(cgroup_path, expected_uid=expected_uid, proc_root=proc_root)

    def authorize(self, connection: Any) -> ChannelContext:
        before = self.directory.stat()
        identity = self.peer.authorize(connection)
        after = self.directory.stat()
        if (
            before.st_ino != self.inode
            or after.st_ino != self.inode
            or int(identity["start_ticks"]) < self.minimum_start_ticks
        ):
            raise PermissionError("Stale process or replaced cgroup")
        channel = ChannelContext(self.binding.channel_id, self.binding.capsule_id)
        if self.broker.resolve(channel) != self.binding:
            raise PermissionError("Binding changed")
        return channel
