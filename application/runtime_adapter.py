"""Member 2 runtime interface. No simulated live-launch fallback."""

from collections.abc import Iterator
from typing import Protocol

from application.models import RuntimeResult, SecurityEvent, TaskContract

REQUIRED_CONTROLS = frozenset(
    {
        "network_none",
        "restricted_filesystem",
        "no_new_privileges",
        "resource_limits",
        "sensor_ready",
        "peer_verified",
    }
)


class RuntimeAdapter(Protocol):
    def launch(self, contract_ref: TaskContract) -> RuntimeResult: ...
    def inspect(self, capsule_id: str) -> RuntimeResult: ...
    def terminate(self, capsule_id: str) -> RuntimeResult: ...
    def observe(self) -> Iterator[SecurityEvent]: ...


class UnavailableRuntime:
    def launch(self, contract_ref: TaskContract) -> RuntimeResult:
        return RuntimeResult(
            state="failed", readiness_passed=False, reason="Member 2 Linux runtime not connected"
        )

    def inspect(self, capsule_id: str) -> RuntimeResult:
        return RuntimeResult(
            state="failed", readiness_passed=False, reason="Runtime inspection unavailable"
        )

    def terminate(self, capsule_id: str) -> RuntimeResult:
        return RuntimeResult(
            state="failed", readiness_passed=False, reason="Termination not verified"
        )

    def observe(self) -> Iterator[SecurityEvent]:
        return iter(())
