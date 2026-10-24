"""Staged, host-identified capsules with durable independent deadline enforcement.

This is a launcher building block, not an assertion of sensor readiness. Admission
requires a trusted callback; the application retains its fail-closed default adapter.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from .platform import DockerLab, PlatformError, command, verify_inspect
from .schema import parse_time, timestamp, validate_contract
from .transport import process_identity

ENTRYPOINT = ["python", "-I", "/opt/agentguard/admission.py"]


def deadline_reached(value):
    return (
        parse_time(value["deadline"]) <= datetime.now(UTC)
        or value["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        or time.monotonic() >= value["monotonic_deadline"]
    )


def private_directory(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise PlatformError("absolute non-symlink trusted directory required")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISDIR(info.st_mode):
        raise PlatformError("trusted directory must be root-owned mode 700")
    return path.resolve()


class RuntimeRecord:
    def __init__(self, path: Path):
        self.path = Path(path)
        if not re.fullmatch(r"capsule-[a-f0-9]{32}\.json", self.path.name):
            raise PlatformError("invalid runtime record")

    @contextmanager
    def lock(self):
        import fcntl

        descriptor = os.open(
            self.path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def read(self):
        descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor) as stream:
            info = os.fstat(stream.fileno())
            if (
                info.st_uid != 0
                or info.st_mode & 0o077
                or not stat.S_ISREG(info.st_mode)
                or info.st_size > 32768
            ):
                raise PlatformError("untrusted runtime record")
            return json.load(stream)

    def write(self, value):
        temporary = self.path.with_suffix("." + uuid4().hex + ".tmp")
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "w") as stream:
                json.dump(value, stream, sort_keys=True, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)


class StagedCapsules:
    def __init__(
        self,
        image_id: str,
        *,
        state_root=Path("/var/lib/agentguard/runtime"),
        channel_root=Path("/run/agentguard/channels"),
        runner=command,
        admission_check: Callable[[dict], bool] | None = None,
    ):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise PlatformError("rootful local Linux is required")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
            raise PlatformError("reviewed immutable local image ID required")
        self.image_id = image_id
        self.state_root = private_directory(Path(state_root))
        self.channel_root = private_directory(Path(channel_root))
        self.run = runner
        self.lab = DockerLab(runner=runner)
        self.admission_check = admission_check

    def record(self, capsule_id):
        if not re.fullmatch(r"capsule-[a-f0-9]{32}", capsule_id):
            raise PlatformError("unknown capsule identifier")
        return RuntimeRecord(self.state_root / (capsule_id + ".json"))

    def _inspect(self, value):
        info = self.lab.inspect(value["container_id"])
        labels = info.get("Config", {}).get("Labels", {})
        if (
            labels.get("agentguard.capsule_id") != value["capsule_id"]
            or labels.get("agentguard.mode") != "staged"
        ):
            raise PlatformError("runtime does not own this container")
        return info

    def recover(self):
        """Re-establish independent deadline monitors after a trusted service restart."""
        recovered = []
        for path in self.state_root.glob("capsule-*.json"):
            record = RuntimeRecord(path)
            with record.lock():
                value = record.read()
                if value["state"] == "contained":
                    continue
                self._inspect(value)
            self._spawn_watchdog(record)
            recovered.append(value["capsule_id"])
        return recovered

    @staticmethod
    def _spawn_watchdog(record):
        with open(os.devnull, "wb") as null:
            subprocess.Popen(  # noqa: S603 - fixed module and root-owned validated record
                [sys.executable, "-m", "agentguard.watchdog", str(record.path)],
                stdin=subprocess.DEVNULL,
                stdout=null,
                stderr=null,
                start_new_session=True,
                close_fds=True,
                cwd=Path(__file__).resolve().parents[1],
            )

    def prepare(self, contract: dict):
        contract = validate_contract(contract)
        checks = self.lab.preflight()
        if any(c.status != "passed" for c in checks if c.mandatory):
            raise PlatformError("baseline runtime preflight refused")
        capsule_id = "capsule-" + uuid4().hex
        channel = self.channel_root / capsule_id
        channel.mkdir(mode=0o700)
        args = self.lab.create_args(contract, self.image_id, "lab-" + uuid4().hex)
        args[args.index("--name") + 1] = capsule_id
        # Remove the fixed lab's entrypoint and command, retain its reviewed controls.
        position = args.index("--entrypoint=python")
        args = args[:position] + [
            "--label",
            "agentguard.mode=staged",
            "--label",
            "agentguard.capsule_id=" + capsule_id,
            "--mount",
            f"type=bind,src={channel},dst=/run/agentguard,readonly,bind-propagation=rprivate",
            "--entrypoint=python",
            self.image_id,
            "-I",
            "/opt/agentguard/admission.py",
        ]
        container_id = self.run(args)
        record = self.record(capsule_id)
        deadline = min(
            parse_time(contract["expires_at"]),
            datetime.now(UTC) + timedelta(seconds=contract["limits"]["max_execution_seconds"]),
        )
        value = {
            "schema_version": "1.0",
            "capsule_id": capsule_id,
            "container_id": container_id,
            "image_id": self.image_id,
            "task_id": contract["task_id"],
            "contract_version": contract["contract_version"],
            "channel_directory": str(channel),
            "deadline": deadline.isoformat(),
            "created_at": timestamp(),
            "monotonic_deadline": time.monotonic()
            + max(0, (deadline - datetime.now(UTC)).total_seconds()),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "state": "prepared",
            "admitted": False,
            "requested_stop": False,
            "identity": None,
            "descendants_exited": False,
            "channel_revoked": False,
        }
        try:
            effective = self.lab.inspect(container_id)
            effective["Config"]["Entrypoint"] = (effective["Config"].get("Entrypoint") or []) + (
                effective["Config"].get("Cmd") or []
            )
            effective["Config"]["Cmd"] = []
            failures = verify_inspect(
                effective, contract, self.image_id, capsule_mount=channel, entrypoint=ENTRYPOINT
            )
            if failures:
                raise PlatformError("effective staged profile refused: " + "; ".join(failures))
            with record.lock():
                record.write(value)
            # A separate process exists before container start. Request failure or
            # application termination cannot remove the workload's deadline.
            self._spawn_watchdog(record)
            validate_contract(contract)
            self.run(["docker", "start", container_id])
            live = self._inspect(value)
            pid = live["State"]["Pid"]
            if not pid:
                raise PlatformError("bootstrap exited before trusted identity registration")
            identity = process_identity(pid)
            cgroup = self.lab._cgroup(pid)
            if not (cgroup / "cgroup.kill").is_file():
                raise PlatformError("kernel cgroup.kill support required before admission")
            identity["cgroup_inode"] = cgroup.stat().st_ino
            identity["process_start_observed_at"] = live["State"]["StartedAt"]
            if process_identity(pid) != {k: identity[k] for k in ("pid", "start_ticks", "cgroup")}:
                raise PlatformError("process changed during registration")
            with record.lock():
                value = record.read()
                if value["state"] != "prepared":
                    raise PlatformError("watchdog refused staged workload")
                value.update(identity=identity, state="staged")
                record.write(value)
            return value
        except BaseException:
            if record.path.exists():
                self.terminate(capsule_id)
            else:
                self.run(["docker", "rm", container_id])
            raise

    def admit(self, capsule_id):
        record = self.record(capsule_id)
        with record.lock():
            value = record.read()
            if value["state"] != "staged" or value["requested_stop"] or deadline_reached(value):
                raise PlatformError("capsule cannot be admitted")
            if self.admission_check is None or not self.admission_check(value):
                raise PlatformError("trusted admission and coverage check refused")
            live = self._inspect(value)
            identity = value["identity"]
            if not live["State"]["Running"] or process_identity(live["State"]["Pid"]) != {
                k: identity[k] for k in ("pid", "start_ticks", "cgroup")
            }:
                raise PlatformError("capsule identity changed before admission")
            cgroup = self.lab._cgroup(identity["pid"])
            if cgroup.stat().st_ino != identity["cgroup_inode"]:
                raise PlatformError("capsule cgroup was replaced")
            directory = Path(value["channel_directory"])
            if not stat.S_ISSOCK((directory / "broker.sock").stat().st_mode):
                raise PlatformError("registered broker socket missing")
            descriptor = os.open(
                directory / "admitted", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(b"admitted-v1\n")
                stream.flush()
                os.fsync(stream.fileno())
            value["admitted"] = True
            record.write(value)

    def inspect(self, capsule_id):
        record = self.record(capsule_id)
        with record.lock():
            value = record.read()
            live = self._inspect(value)
            return {
                **value,
                "runtime_running": live["State"]["Running"],
                "exit_code": live["State"].get("ExitCode"),
            }

    def terminate(self, capsule_id):
        record = self.record(capsule_id)
        with record.lock():
            value = record.read()
            value["requested_stop"] = True
            record.write(value)
        return contain_record(record)


def contain_record(record: RuntimeRecord):
    """Verify kernel lifecycle and revoke only the exact recorded dedicated channel."""
    with record.lock():
        value = record.read()
        lab = DockerLab()
        identity = value.get("identity")
        if identity is not None and (value["requested_stop"] or deadline_reached(value)):
            root = lab.cgroup_root.resolve()
            cgroup = (root / identity["cgroup"].lstrip("/")).resolve()
            if cgroup == root or not cgroup.is_relative_to(root):
                raise PlatformError("unsafe captured cgroup")
            if cgroup.exists():
                if cgroup.stat().st_ino != identity["cgroup_inode"]:
                    raise PlatformError("captured cgroup identity changed")
                # Deadline enforcement does not depend on a responsive Docker API.
                try:
                    (cgroup / "cgroup.kill").write_text("1")
                except OSError as exc:
                    # Preserve the kernel failure, but still attempt verified runtime
                    # containment; a missing kernel interface must not skip Docker kill.
                    value["kernel_kill_error"] = type(exc).__name__
        live = lab.inspect(value["container_id"])
        labels = live.get("Config", {}).get("Labels", {})
        if labels.get("agentguard.capsule_id") != value["capsule_id"]:
            raise PlatformError("container ownership mismatch")
        if live["State"].get("Running") and identity is None:
            pid = live["State"]["Pid"]
            identity = process_identity(pid)
            identity["cgroup_inode"] = lab._cgroup(pid).stat().st_ino
            value["identity"] = identity
        try:
            if identity is not None:
                root = lab.cgroup_root.resolve()
                cgroup = (root / identity["cgroup"].lstrip("/")).resolve()
                if cgroup == root or not cgroup.is_relative_to(root):
                    raise PlatformError("unsafe captured cgroup")
                if cgroup.exists() and cgroup.stat().st_ino != identity["cgroup_inode"]:
                    raise PlatformError("captured cgroup identity changed")
                lab.terminate(value["container_id"], cgroup)
            elif live["State"].get("Status") != "created":
                raise PlatformError("termination has no captured process identity")
            directory = Path(value["channel_directory"])
            if (
                directory.name != value["capsule_id"]
                or directory.parent.stat().st_uid != 0
                or directory.parent.stat().st_mode & 0o077
            ):
                raise PlatformError("channel parent is untrusted")
            (directory / "admitted").unlink(missing_ok=True)
            (directory / "broker.sock").unlink(missing_ok=True)
            value.update(
                state="contained",
                descendants_exited=True,
                channel_revoked=True,
                contained_at=timestamp(),
            )
        except Exception:
            value.update(state="containment_unverified", descendants_exited=False)
            record.write(value)
            raise
        record.write(value)
        return value
