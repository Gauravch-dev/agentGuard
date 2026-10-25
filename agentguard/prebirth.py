"""Start independent process/file/socket capture before a capsule is started.

Subscriptions are proved with real, exact host canaries before docker start.
Only the already-created target container's records reach the private journals.
This closes the attachment race for these streams, not the later AF_PACKET tap,
and does not certify lossless or complete kernel coverage.
"""

import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path
from uuid import uuid4

from agentguard.capsules import private_directory
from agentguard.hook_policy import prebirth_policy
from agentguard.platform import command
from agentguard.policy_control import install_policy, remove_policy
from agentguard.schema import strict_json, timestamp
from agentguard.transport import process_identity


def is_witness(kind, raw, executable, canary, policy):
    field = "process_exec" if kind == "process" else "process_kprobe"
    body = raw.get(field, {})
    source = body.get("process", {})
    if type(source.get("uid")) is not int or source["uid"] != 0:
        return False
    if kind == "process":
        return source.get("binary") == str(executable)
    returned = body.get("return", {}).get("long_arg")
    return (
        body.get("policy_name") == policy
        and body.get("function_name", "").removeprefix("__x64_") == "sys_openat"
        and isinstance(returned, str)
        and re.fullmatch(r"[0-9]{1,19}", returned) is not None
        and int(returned) < 2**63
        and any(arg.get("string_arg") == str(canary) for arg in body.get("args", []))
    )


class PrebirthCapture:
    def __init__(self, value, directory):
        self.value = value
        self.root = private_directory(directory)
        self.policy = "agentguard-" + uuid4().hex
        self.stop, self.lock = threading.Event(), threading.Lock()
        self.errors = set()
        self.processes, self.readers, self.commands = {}, [], {}
        self.canaries = {kind: threading.Event() for kind in ("process", "hooks")}
        self.canary_root = private_directory(Path("/run/agentguard") / ("witness-" + uuid4().hex))
        self.canary = self.canary_root / "ready"
        self.executable = self.canary_root / "probe"
        self.executable.write_bytes(Path("/usr/bin/true").read_bytes())
        self.executable.chmod(0o500)
        self.policy_may_exist = False
        self.prepared_at = None
        self.closed = False
        self.frames = {"process": 0, "hooks": 0}
        self.witness_candidates = []
        self.witnesses = {}

    def read(self, kind, process):
        try:
            with (self.root / (kind + ".jsonl")).open("ab", buffering=0) as journal:
                while not self.stop.is_set():
                    line = process.stdout.readline(65537)
                    if not line:
                        raise EOFError("Source closed")
                    if len(line) > 65536 or not line.endswith(b"\n"):
                        raise ValueError("Invalid source frame")
                    raw = strict_json(line)
                    body = next(
                        (
                            raw[k]
                            for k in ("process_exec", "process_exit", "process_kprobe")
                            if k in raw
                        ),
                        {},
                    )
                    source = body.get("process", {})
                    with self.lock:
                        self.frames[kind] += 1
                        if len(self.witness_candidates) < 8 and (
                            source.get("binary", "").endswith("/true")
                            or source.get("pid") == os.getpid()
                        ):
                            self.witness_candidates.append(
                                {
                                    "kind": kind,
                                    "pid": source.get("pid"),
                                    "parent_pid": body.get("parent", {}).get("pid"),
                                    "binary": source.get("binary"),
                                }
                            )
                    if not self.canaries[kind].is_set() and is_witness(
                        kind, raw, self.executable, self.canary, self.policy
                    ):
                        descriptor = os.open(
                            self.root / (kind + "-witness.json"),
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600,
                        )
                        with os.fdopen(descriptor, "wb") as witness:
                            witness.write(line)
                            witness.flush()
                            os.fsync(witness.fileno())
                        with self.lock:
                            self.witnesses[kind] = {
                                "evidence_reference": "subscription-witness:"
                                + hashlib.sha256(line).hexdigest(),
                                "observed_at": raw.get("time"),
                                "received_at": timestamp(),
                            }
                        self.canaries[kind].set()
                    docker = source.get("docker", "")
                    if not docker:
                        if source.get("uid") == 65532:
                            with self.lock:
                                self.errors.add("PREBIRTH_SOURCE_ATTRIBUTION_GAP")
                        continue
                    if (
                        not isinstance(docker, str)
                        or len(docker) < 12
                        or not self.value["container_id"].startswith(docker)
                    ):
                        continue
                    if kind == "hooks" and body.get("policy_name") != self.policy:
                        continue
                    if journal.tell() + len(line) > 16 * 1024 * 1024:
                        raise ValueError("Journal quota exceeded")
                    journal.write(line)
                    os.fsync(journal.fileno())
        except Exception:
            if not self.stop.is_set():
                with self.lock:
                    self.errors.add(kind.upper() + "_PREBIRTH_STREAM_FAILED")

    def begin(self):
        try:
            sensor = json.loads(command(["docker", "inspect", "agentguard-tetragon"]))[0]
            expected = json.loads(
                (Path(__file__).resolve().parents[1] / "platform/versions.json").read_text()
            )["tetragon_image"]
            if (
                sensor["Config"]["Image"] != expected
                or sensor["Config"]["Labels"].get("agentguard.component") != "host-sensor"
                or not sensor["State"]["Running"]
            ):
                raise PermissionError("Pinned managed sensor unavailable")
            pid = sensor["State"]["Pid"]
            before = process_identity(pid)
            sensor_namespace = Path(f"/proc/{pid}/ns/mnt").stat().st_ino
            if (
                sensor_namespace == Path("/proc/self/ns/mnt").stat().st_ino
                or process_identity(pid) != before
            ):
                raise PermissionError("Sensor namespace changed or is the host")
            policy = prebirth_policy(
                self.policy,
                self.canary,
                sensor_namespace,
                Path("/proc/self/ns/mnt").stat().st_ino,
            )
            path = self.root / "prebirth-policy.json"
            path.write_text(json.dumps(policy))
            path.chmod(0o600)
            self.policy_may_exist = True
            install_policy(path, self.policy)
            policies = json.loads(
                command(
                    ["docker", "exec", "agentguard-tetragon", "tetra", "tp", "list", "-o", "json"]
                )
            )
            if not any(
                p.get("name") == self.policy and p.get("state") == "TP_STATE_ENABLED"
                for p in policies.get("policies", [])
            ):
                raise RuntimeError("Pre-birth policy not enabled")
            common = [
                "/usr/bin/docker",
                "exec",
                "agentguard-tetragon",
                "timeout",
                "-s",
                "TERM",
                "-k",
                "2",
                "180",
                "tetra",
                "getevents",
            ]
            for kind, selection in (
                ("process", ["--event-types", "PROCESS_EXEC,PROCESS_EXIT"]),
                ("hooks", ["--policy-names", self.policy]),
            ):
                args = (
                    common + selection + ["--exclude-fields", "process.arguments,parent.arguments"]
                )
                self.commands[kind] = args
                (self.root / (kind + ".jsonl")).touch(mode=0o600)
                with (self.root / (kind + ".stderr")).open("ab") as errors:
                    process = subprocess.Popen(  # noqa: S603 - fixed trusted host collectors
                        args,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=errors,
                        start_new_session=True,
                    )
                self.processes[kind] = process
                reader = threading.Thread(target=self.read, args=(kind, process), daemon=True)
                self.readers.append(reader)
                reader.start()
            # The pinned source's event cache can delay host parent metadata for
            # 15 x 2 seconds. Wait for actual witnesses, never assume attachment
            # from elapsed time. The original workload deadline still applies.
            end = time.monotonic() + 35
            while time.monotonic() < end:
                # No agent-controlled path or executable is involved. Both
                # witnesses must have crossed the actual sensor subscription.
                witness = subprocess.Popen([str(self.executable)])  # noqa: S603 - root-private copy of host true
                witness.wait(timeout=1)
                with self.canary.open("w"):
                    pass
                if all(event.wait(0.05) for event in self.canaries.values()):
                    break
                with self.lock:
                    if self.errors:
                        raise RuntimeError("Pre-birth source failed")
                time.sleep(0.2)
            if not all(event.is_set() for event in self.canaries.values()):
                raise RuntimeError("Actual pre-birth subscription witnesses missing")
            if any(p.poll() is not None for p in self.processes.values()):
                raise RuntimeError("Pre-birth source exited")
            self.prepared_at = timestamp()
            # Exact source records remain in the original journals; this is a
            # truthful attachment fact, never a complete coverage interval.
            (self.root / "prebirth.json").write_text(json.dumps(self.proof()))
            (self.root / "prebirth.json").chmod(0o600)
        except BaseException as exc:
            (self.root / "prebirth-failure.json").write_text(
                json.dumps(
                    {
                        "observed_at": timestamp(),
                        "type": type(exc).__name__,
                        "reason": str(exc),
                        "proof": self.proof(),
                    }
                )
            )
            (self.root / "prebirth-failure.json").chmod(0o600)
            self.close()
            raise

    def proof(self):
        with self.lock:
            return {
                "prepared_at": self.prepared_at,
                "process_subscription_witnessed": self.canaries["process"].is_set(),
                "hook_subscription_witnessed": self.canaries["hooks"].is_set(),
                "errors": sorted(self.errors),
                "packet_prebirth_coverage": False,
                "complete_coverage": False,
                "frames_received": dict(self.frames),
                "witnesses": dict(self.witnesses),
            }

    def close(self):
        if self.closed:
            return
        self.stop.set()
        for process in self.processes.values():
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for process in self.processes.values():
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
        for reader in self.readers:
            reader.join(timeout=3)
        for process in self.processes.values():
            if process.stdout is not None:
                process.stdout.close()
        if self.policy_may_exist:
            remove_policy(self.policy)
            self.policy_may_exist = False
        self.cleanup_canary()
        self.closed = True

    def cleanup_canary(self):
        self.canary.unlink(missing_ok=True)
        self.executable.unlink(missing_ok=True)
        if self.canary_root.exists():
            self.canary_root.rmdir()
