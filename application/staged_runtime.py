"""Application adapter for Member 2's real staged controller.

No production admission reviewer is supplied yet. Preparing a trusted bootstrap
does not admit agent code or claim sensor readiness. Tests inject explicit doubles.
"""

import asyncio
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from application.broker_transport import serve_socket
from application.brokers import Broker
from application.member2_bridge import Member2ChannelAuthorizer, Member2RuntimeAdapter
from application.models import Binding, RuntimeResult, State, TaskContract, now

BASE_CONTROLS = ("network_none", "restricted_filesystem", "no_new_privileges", "resource_limits")


class BrokerSockets:
    """Own socket listeners on a dedicated loop; HTTP handlers remain synchronous."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.servers: dict[str, asyncio.AbstractServer] = {}

    def open(self, value: dict, binding: Binding, broker: Broker) -> None:
        identity = value["identity"]
        authorizer = Member2ChannelAuthorizer(
            broker,
            binding,
            identity["cgroup"],
            int(identity["start_ticks"]),
            identity["cgroup_inode"],
        )

        async def start() -> None:
            self.servers[binding.capsule_id] = await serve_socket(
                Path(value["channel_directory"]) / "broker.sock",
                broker,
                authorizer=authorizer,
                capsule_uid=65532,
            )

        future = asyncio.run_coroutine_threadsafe(start(), self.loop)
        try:
            future.result(timeout=10)
        except BaseException:
            future.cancel()
            raise

    def close(self, capsule_id: str) -> None:
        async def stop() -> None:
            server = self.servers.pop(capsule_id, None)
            if server is not None:
                server.close()
                await server.wait_closed()

        asyncio.run_coroutine_threadsafe(stop(), self.loop).result(timeout=10)

    def shutdown(self) -> None:
        for capsule_id in list(self.servers):
            self.close(capsule_id)

        async def drain() -> None:
            tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        asyncio.run_coroutine_threadsafe(drain(), self.loop).result(timeout=10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("Broker listener did not stop")
        self.loop.close()


class StagedRuntimeAdapter(Member2RuntimeAdapter):
    def __init__(
        self,
        controller: Any,
        host_id: str,
        *,
        sockets: Any = None,
        admission_review: Callable[[dict], bool] | None = None,
    ) -> None:
        super().__init__(lab=controller.lab, approved_image=controller.image_id)
        self.controller, self.host_id = controller, host_id
        self.sockets = sockets
        self.admission_review = admission_review

    def launch(self, contract_ref: TaskContract) -> RuntimeResult:
        value = self.controller.prepare(contract_ref.model_dump(mode="json"))
        try:
            identity = value["identity"]
            binding = Binding(
                task_id=value["task_id"],
                contract_version=value["contract_version"],
                capsule_id=value["capsule_id"],
                host_id=self.host_id,
                cgroup_id="cg-" + str(identity["cgroup_inode"]),
                process_start=datetime.fromisoformat(identity["process_start_observed_at"]),
                registered_at=now(),
                channel_id=uuid4().hex,
            )
            if (
                binding.task_id != contract_ref.task_id
                or binding.contract_version != contract_ref.contract_version
            ):
                raise ValueError("Controller returned another contract")
            return RuntimeResult(
                state="launch_requested",
                readiness_passed=False,
                controls=BASE_CONTROLS,
                reason="Bootstrap staged; agent admission awaits verified monitoring and platform review",
                binding=binding,
            )
        except BaseException:
            self.controller.terminate(value["capsule_id"])
            raise

    def record_for(self, binding: Binding) -> dict:
        value: dict = self.controller.inspect(binding.capsule_id)
        identity = value["identity"]
        if (
            value["task_id"] != binding.task_id
            or value["contract_version"] != binding.contract_version
            or self.host_id != binding.host_id
            or "cg-" + str(identity["cgroup_inode"]) != binding.cgroup_id
            or datetime.fromisoformat(identity["process_start_observed_at"])
            != binding.process_start
        ):
            raise PermissionError("Runtime identity no longer matches the registered binding")
        return value

    def open_channel(self, binding: Binding, broker: Broker) -> None:
        if self.sockets is None:
            self.sockets = BrokerSockets()
        self.sockets.open(self.record_for(binding), binding, broker)

    def reviewed(self, binding: Binding) -> bool:
        # There is deliberately no HTTP flag or environment switch to bypass this.
        return self.admission_review is not None and self.admission_review(self.record_for(binding))

    def capabilities(self) -> dict:
        return {
            **super().capabilities(),
            "staged_launcher_connected": True,
            "admission_review_connected": self.admission_review is not None,
            "protected_execution_ready": False,
        }

    def admit(self, binding: Binding, check: Callable[[dict], bool]) -> None:
        self.record_for(binding)
        self.controller.admission_check = check
        self.controller.admit(binding.capsule_id)

    def inspect(self, capsule_id: str) -> RuntimeResult:
        value = self.controller.inspect(capsule_id)
        exited = bool(
            value["state"] == "contained"
            and value["descendants_exited"]
            and value["channel_revoked"]
            and not value["runtime_running"]
        )
        state: State = "running" if value["admitted"] else "launch_requested"
        if exited:
            state = (
                "interrupted"
                if value["requested_stop"]
                else ("completed" if value["exit_code"] == 0 else "failed")
            )
        return RuntimeResult(
            state=state,
            readiness_passed=False,
            controls=BASE_CONTROLS,
            reason="Exit and channel revocation verified"
            if exited
            else "Independent termination not yet verified",
            descendants_exited=exited,
        )

    def terminate(self, capsule_id: str) -> RuntimeResult:
        # Durable application revocation happens before this method is called.
        try:
            if self.sockets is not None:
                self.sockets.close(capsule_id)
        finally:
            self.controller.terminate(capsule_id)
        return self.inspect(capsule_id)

    def shutdown(self) -> None:
        if self.sockets is not None:
            self.sockets.shutdown()
