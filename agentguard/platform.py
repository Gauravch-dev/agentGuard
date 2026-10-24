"""Trusted Docker isolation lab. No arbitrary commands, mounts or runtime flags."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import platform as host_platform
import re
import shutil
import subprocess
import time
from uuid import uuid4

from .schema import timestamp, validate_contract


class PlatformError(RuntimeError):
    pass


@dataclass
class Check:
    name: str
    status: str
    evidence: object
    mandatory: bool = True


def command(args, *, timeout=15):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlatformError(f"{args[0]} unavailable or timed out: {type(exc).__name__}") from exc
    if result.returncode:
        raise PlatformError(f"{args[0]} returned {result.returncode}: {result.stderr.strip()[:512]}")
    return result.stdout.strip()


def host_audit():
    linux = host_platform.system() == "Linux"
    checks = [Check("linux_host", "supported" if linux else "unsupported", host_platform.platform()),
              Check("local_docker_cli", "supported" if shutil.which("docker") else "unsupported", shutil.which("docker")),
              Check("cgroup_v2", "supported" if linux and Path("/sys/fs/cgroup/cgroup.controllers").exists() else "unsupported", "presence of /sys/fs/cgroup/cgroup.controllers"),
              Check("btf", "supported" if linux and Path("/sys/kernel/btf/vmlinux").is_file() else "unsupported", "presence of /sys/kernel/btf/vmlinux"),
              Check("python", "supported", host_platform.python_version())]
    if linux:
        try:
            info = json.loads(command(["docker", "info", "--format", "{{json .}}" ]))
            checks.extend([
                Check("docker_linux", "supported" if info.get("OSType") == "linux" else "unsupported", info.get("OSType")),
                Check("docker_cgroup_v2", "supported" if info.get("CgroupVersion") == "2" else "unsupported", info.get("CgroupVersion")),
                Check("docker_security_options", "supported" if any("seccomp" in s for s in info.get("SecurityOptions", [])) else "unsupported", info.get("SecurityOptions")),
                Check("docker_version", "supported", info.get("ServerVersion")),
            ])
        except (PlatformError, ValueError) as exc:
            checks.append(Check("docker_daemon", "unsupported", str(exc)))
    for feature in ("namespace_effectiveness", "apparmor_or_selinux", "clock_synchronization", "sensor_process_probes", "sensor_loss_accounting", "broker_peer_identity", "network_flow_visibility", "termination_descendants"):
        checks.append(Check(feature, "untested", "requires an owned Linux security-lab run"))
    checks.append(Check("protected_execution_integration", "unsupported", "live coverage attestation and full runtime/broker wiring are not implemented"))
    return {"observed_at": timestamp(), "host": host_platform.node(), "kernel": host_platform.release(),
            "architecture": host_platform.machine(), "cpu_count": os.cpu_count(),
            "disk_free_bytes": shutil.disk_usage(Path.cwd()).free,
            "checks": [asdict(c) for c in checks], "security_claim": "capability inventory; presence alone does not establish effective isolation"}


def verify_inspect(info, contract, image_id):
    """Inspect the stopped container before any image code starts."""
    h, c = info.get("HostConfig", {}), info.get("Config", {})
    limits = contract["limits"]
    failures = []

    def require(condition, label):
        if not condition:
            failures.append(label)

    require(info.get("Image") == image_id, "immutable image mismatch")
    require(c.get("User") == "65532:65532", "unprivileged fixed UID/GID")
    require(c.get("Entrypoint") == ["python", "-I", "/opt/agentguard/isolation_probe.py"], "fixed lab entrypoint")
    require(c.get("Cmd") in (None, []), "unexpected command override")
    require(c.get("WorkingDir") == "/work", "working directory")
    require(h.get("NetworkMode") == "none", "network deny")
    require(h.get("Privileged") is False, "privileged runtime")
    require(h.get("ReadonlyRootfs") is True, "read-only root")
    require({s.upper() for s in h.get("CapDrop", [])} == {"ALL"}, "drop capabilities")
    require(not h.get("CapAdd"), "capability additions")
    security = h.get("SecurityOpt", [])
    require(any(s in {"no-new-privileges", "no-new-privileges:true"} for s in security), "no-new-privileges")
    require(not any("unconfined" in s for s in security), "unconfined profile")
    require(h.get("Memory") == limits["max_memory_mb"] * 1024**2, "memory limit")
    require(h.get("MemorySwap") == h.get("Memory"), "swap limit")
    require(h.get("PidsLimit") == limits["max_processes"], "process limit")
    require(h.get("NanoCpus") == 1_000_000_000, "CPU limit")
    require(h.get("PidMode", "") == "" and h.get("IpcMode") == "private", "PID/IPC namespace")
    require(h.get("CgroupnsMode") == "private", "cgroup namespace")
    require(not h.get("Binds") and not h.get("Mounts") and not info.get("Mounts"), "unexpected host mount")
    require(not h.get("Devices") and not h.get("DeviceRequests"), "device exposure")
    require(not h.get("VolumesFrom") and not h.get("Links"), "cross-container exposure")
    require(not c.get("Volumes"), "image-declared volumes")
    require(not c.get("Healthcheck"), "image healthcheck is not permitted")
    require(set(h.get("Tmpfs", {})) == {"/tmp", "/work"}, "bounded temporary mounts")
    for path, megabytes in (("/tmp", 16), ("/work", 16)):
        options = set(h.get("Tmpfs", {}).get(path, "").split(","))
        require({"rw", "noexec", "nosuid", "nodev", f"size={megabytes}m", "uid=65532", "gid=65532", "mode=700"} <= options, f"tmpfs restrictions: {path}")
    require(h.get("LogConfig", {}).get("Type") == "local", "bounded runtime logs")
    require(h.get("LogConfig", {}).get("Config", {}).get("max-size") == "1m", "log size limit")
    return failures


class DockerLab:
    def __init__(self, *, runner=command, proc_root=Path("/proc"), cgroup_root=Path("/sys/fs/cgroup")):
        self.run = runner
        self.proc_root, self.cgroup_root = Path(proc_root), Path(cgroup_root)
        self.last_container_id = None

    def preflight(self, *, protected=False):
        checks = []
        if host_platform.system() != "Linux":
            return [Check("linux_host", "failed", "Linux required; no Windows fallback")]
        try:
            context = json.loads(self.run(["docker", "context", "inspect"]))[0]
            endpoint = context["Endpoints"]["docker"]["Host"]
            if not endpoint.startswith("unix://") or os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT"):
                raise PlatformError("requires default local Unix socket; remote/overridden daemons cannot establish host identity")
            info = json.loads(self.run(["docker", "info", "--format", "{{json .}}" ]))
            checks.append(Check("linux_daemon", "passed" if info.get("OSType") == "linux" else "failed", info.get("OSType")))
            checks.append(Check("cgroup_v2", "passed" if info.get("CgroupVersion") == "2" and (self.cgroup_root / "cgroup.controllers").exists() else "failed", info.get("CgroupVersion")))
            options = info.get("SecurityOptions", [])
            checks.append(Check("seccomp_enabled", "passed" if any("seccomp" in s for s in options) else "failed", options))
            checks.append(Check("tested_uid_mapping", "failed" if any("rootless" in s or "userns" in s for s in options) else "passed", "initial adapter supports rootful local Docker only; userns variants need peer-identity tests"))
        except (PlatformError, ValueError, KeyError, IndexError) as exc:
            checks.append(Check("local_daemon", "failed", str(exc)))
        if protected:
            checks.append(Check("independent_sensor_coverage", "failed", "live sensor interval attestation is pending; protected launch refused"))
            checks.append(Check("broker_container_integration", "failed", "cross-capsule live acceptance tests have not passed"))
        return checks

    @staticmethod
    def create_args(contract, image_id, capsule_id):
        validate_contract(contract)
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
            raise PlatformError("immutable local Docker image ID required")
        if not re.fullmatch(r"lab-[a-f0-9]{32}", capsule_id):
            raise PlatformError("launcher-generated capsule identifier required")
        limits = contract["limits"]
        return [
            "docker", "create", "--name", capsule_id, "--pull=never", "--network=none",
            "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--read-only", "--ipc=private", "--cgroupns=private", "--pids-limit", str(limits["max_processes"]),
            "--memory", f"{limits['max_memory_mb']}m", "--memory-swap", f"{limits['max_memory_mb']}m",
            "--cpus=1", "--restart=no", "--ulimit=nofile=256:256", "--ulimit=core=0:0",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=700",
            "--tmpfs=/work:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=700",
            "--workdir=/work", "--log-driver=local", "--log-opt=max-size=1m", "--log-opt=max-file=1",
            "--label", f"agentguard.task_id={contract['task_id']}",
            "--label", f"agentguard.contract_version={contract['contract_version']}",
            "--label", "agentguard.mode=isolation-lab",
            "--entrypoint=python", image_id, "-I", "/opt/agentguard/isolation_probe.py",
        ]

    def inspect(self, container_id):
        if not re.fullmatch(r"[a-f0-9]{64}", container_id):
            raise PlatformError("invalid trusted container ID")
        return json.loads(self.run(["docker", "inspect", container_id]))[0]

    def _cgroup(self, pid):
        content = (self.proc_root / str(pid) / "cgroup").read_text()
        matches = [line[3:] for line in content.splitlines() if line.startswith("0::/")]
        if len(matches) != 1 or matches[0] == "/":
            raise PlatformError("unverified cgroup identity")
        root = self.cgroup_root.resolve()
        path = (root / matches[0].lstrip("/")).resolve()
        if not path.is_relative_to(root) or path == root:
            raise PlatformError("unsafe cgroup path")
        return path

    @staticmethod
    def _populated(cgroup):
        try:
            values = dict(line.split() for line in (cgroup / "cgroup.events").read_text().splitlines())
            return values.get("populated") != "0"
        except FileNotFoundError:
            return False  # Kernel removed the captured cgroup; it cannot hold live processes.

    def terminate(self, container_id, cgroup):
        if cgroup is None:
            raise PlatformError("no captured cgroup: termination remains Unverified")
        state = self.inspect(container_id)["State"]
        if state.get("Running"):
            self.run(["docker", "kill", container_id])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = self.inspect(container_id)["State"]
            if not state.get("Running") and not self._populated(cgroup):
                return {"confirmed": True, "container_id": container_id, "cgroup": str(cgroup), "scope": "captured cgroup and descendants"}
            time.sleep(0.05)
        raise PlatformError("termination or descendant exit not confirmed")

    def isolation_lab(self, contract, image):
        validate_contract(contract)
        checks = self.preflight()
        if any(c.status != "passed" for c in checks if c.mandatory):
            raise PlatformError("preflight refused: " + json.dumps([asdict(c) for c in checks]))
        if not isinstance(image, str) or image.startswith("-") or len(image) > 256:
            raise PlatformError("invalid local image reference")
        metadata = json.loads(self.run(["docker", "image", "inspect", image]))[0]
        image_id = metadata["Id"]
        # Images are a trusted administrator input, not agent-selected code.
        if metadata.get("Config", {}).get("Volumes") or metadata.get("Config", {}).get("Healthcheck"):
            raise PlatformError("unapproved image volumes/healthcheck")
        capsule_id = "lab-" + uuid4().hex
        container_id = self.run(self.create_args(contract, image_id, capsule_id))
        if not re.fullmatch(r"[a-f0-9]{64}", container_id):
            raise PlatformError("daemon returned invalid container identity")
        self.last_container_id = container_id
        cgroup, started, termination = None, False, None
        try:
            effective = self.inspect(container_id)
            # CLI's explicit command is represented as Entrypoint + Cmd by Docker.
            normalized = json.loads(json.dumps(effective))
            normalized["Config"]["Entrypoint"] = (effective["Config"].get("Entrypoint") or []) + (effective["Config"].get("Cmd") or [])
            normalized["Config"]["Cmd"] = []
            failures = verify_inspect(normalized, contract, image_id)
            if failures:
                raise PlatformError("effective profile refused: " + "; ".join(failures))
            validate_contract(contract)  # Expiry checked again immediately before start.
            self.run(["docker", "start", container_id])
            started = True
            live = self.inspect(container_id)
            pid = live.get("State", {}).get("Pid", 0)
            if not pid:
                raise PlatformError("capsule ended before trusted cgroup mapping")
            cgroup = self._cgroup(pid)
            deadline = time.monotonic() + min(30, contract["limits"]["max_execution_seconds"])
            while self.inspect(container_id)["State"].get("Running"):
                if time.monotonic() >= deadline:
                    raise PlatformError("lab execution deadline reached")
                time.sleep(0.05)
            state = self.inspect(container_id)["State"]
            raw = self.run(["docker", "logs", container_id])
            if len(raw) > 65_536:
                raise PlatformError("lab report exceeded limit")
            report = json.loads(raw)
            if state.get("ExitCode") != 0 or report.get("passed") is not True:
                raise PlatformError("active isolation probes failed: " + raw[:4096])
            termination = self.terminate(container_id, cgroup)
            return {"mode": "isolation-lab", "capsule_id": capsule_id, "container_id": container_id,
                    "contract_version": contract["contract_version"], "image_id": image_id,
                    "observed_at": timestamp(), "preflight": [asdict(c) for c in checks], "probes": report,
                    "termination": termination, "effective_profile_sha256": hashlib.sha256(json.dumps(effective, sort_keys=True).encode()).hexdigest(),
                    "host_sensor_coverage": "unavailable", "protected_mvp_complete": False}
        finally:
            if started and termination is None:
                try:
                    self.terminate(container_id, cgroup)
                except Exception as exc:
                    # Do not silently report successful cleanup or delete inspect evidence.
                    try:
                        self.run(["docker", "kill", container_id])
                    except PlatformError:
                        pass
                    raise PlatformError(f"containment remains Unverified; preserve container {container_id} for review: {exc}") from exc
            self.run(["docker", "rm", container_id])
