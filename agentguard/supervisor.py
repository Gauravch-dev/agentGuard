"""Continuous independent process/hook/packet observers for the staged runtime.

All collectors and credentials stay on the trusted host. This supported baseline
has known scope/start gaps, so it reports partial/unavailable coverage and refuses
admission. Completing transport/health plumbing must not erase those limitations.
"""

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from agentguard.capsules import private_directory
from agentguard.export_queue import ExportQueue
from agentguard.hook_policy import HookNormalizer, capsule_policy
from agentguard.observer_health import SourceHealth, clock_compatible, health_reasons, metric_delta
from agentguard.platform import command
from agentguard.schema import parse_time, strict_json, timestamp
from agentguard.sensors import TetragonNormalizer, Workload
from agentguard.transport import process_identity
from application.member2_bridge import translate_member2_event
from application.models import Binding, Coverage, SecurityEvent

ROOT = Path(__file__).resolve().parents[1]
SOURCE_IDS = {"process": "linux-process-01", "hooks": "linux-hooks-01", "packet": "linux-packet-01"}
METRICS = (
    "tetragon_observer_ringbuf_events_lost_total",
    "tetragon_observer_ringbuf_queue_events_lost_total",
    "tetragon_events_missing_process_info_total",
    "tetragon_events_export_failed_total",
    "tetragon_export_ratelimit_events_dropped_total",
    "tetragon_notify_overflowed_events_total",
    "tetragon_field_filter_failed_total",
    "tetragon_observer_ringbuf_errors_total",
)


def sensor_metrics():
    import re

    result = {}
    observed_families = set()
    body = command(
        ["docker", "exec", "agentguard-tetragon", "wget", "-qO-", "http://127.0.0.1:2112/metrics"],
        timeout=3,
    )
    for line in body.splitlines():
        match = re.fullmatch(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([0-9]+(?:\.0+)?)", line)
        if match and match[1] in METRICS:
            observed_families.add(match[1])
            result[match[1] + (match[2] or "")] = int(match[3].split(".")[0])
    for family in set(METRICS) - observed_families:
        result[family] = None
    return result


def verified_mount_namespace(value):
    identity = value["identity"]
    expected = {key: identity[key] for key in ("pid", "start_ticks", "cgroup")}
    if process_identity(identity["pid"]) != expected:
        raise PermissionError("Observer workload identity changed before policy attachment")
    cgroup = Path("/sys/fs/cgroup") / identity["cgroup"].lstrip("/")
    if cgroup.stat().st_ino != identity["cgroup_inode"]:
        raise PermissionError("Observer cgroup changed before policy attachment")
    inode = Path(f"/proc/{identity['pid']}/ns/mnt").stat().st_ino
    if inode == Path("/proc/self/ns/mnt").stat().st_ino:
        raise PermissionError("Host mount namespace refused")
    if (
        process_identity(identity["pid"]) != expected
        or cgroup.stat().st_ino != identity["cgroup_inode"]
    ):
        raise PermissionError("Observer identity changed during namespace capture")
    return inode


class ContinuousSupervisor:
    def __init__(self, controller, sensors, host_id, *, state_root, api_port=8000):
        self.controller, self.sensors, self.host_id = controller, sensors, host_id
        self.root = private_directory(Path(state_root))
        self.port = api_port
        for kind, sensor_id in SOURCE_IDS.items():
            identity = sensors.get(sensor_id)
            expected = "network_sensor" if kind == "packet" else "host_sensor"
            if identity is None or identity.host_id != host_id or expected not in identity.sources:
                raise ValueError("Distinct registered process/hook/packet sources required")
        self.lock = threading.Lock()
        self.workers = {}
        self.recovery_stop = threading.Event()
        self.recovery_thread = None

    def recover(self):
        # Recovery only forwards immutable old observations. It does not restart
        # old agents, restore channels or reconstruct a healthy sensor interval.
        self.recovery_thread = threading.Thread(target=self.replay_pending, daemon=True)
        self.recovery_thread.start()

    def replay_pending(self):
        pending = True
        for _ in range(10):
            if not pending or self.recovery_stop.wait(1):
                return
            pending = False
            summary = []
            for path in list(self.root.glob("capsule-*/manifest.json"))[:64]:
                if self.recovery_stop.is_set():
                    return
                try:
                    directory = private_directory(path.parent)
                    if not re.fullmatch(r"capsule-[a-f0-9]{32}", directory.name):
                        raise ValueError("Invalid journal identity")
                    with self.lock:
                        if directory.name in self.workers:
                            continue
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(descriptor) as source:
                        info = os.fstat(source.fileno())
                        if info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 32768:
                            raise PermissionError("Private manifest required")
                        manifest = strict_json(source.read())
                    binding = Binding.model_validate(manifest["binding"])
                    if binding.capsule_id != directory.name or binding.host_id != self.host_id:
                        raise ValueError("Journal binding mismatch")
                    workload = Workload(**manifest["workload"])
                    for kind, sensor_id in SOURCE_IDS.items():
                        queue = ExportQueue(
                            private_directory(directory / (kind + "-queue")),
                            sensor_id,
                            api_port=self.port,
                        )
                        try:
                            raw = directory / (kind + ".jsonl")
                            if raw.exists():
                                replay = JournalReplay(binding, workload, manifest["policy"], queue)
                                queue.tail(
                                    raw,
                                    lambda line, ref, kind=kind, replay=replay: replay.normalize(
                                        kind, line, ref
                                    ),
                                    endpoint="events" if kind == "packet" else "member2",
                                )
                            queue.drain(self.sensors[sensor_id].token, max_frames=128)
                            state = queue.status()
                            pending |= state["pending"] > 0
                            summary.append(
                                {"capsule_id": binding.capsule_id, "sensor_id": sensor_id, **state}
                            )
                        finally:
                            queue.close()
                except Exception:
                    summary.append(
                        {"capsule_id": path.parent.name, "status": "JOURNAL_RECOVERY_HELD"}
                    )
            ObserverWorker.write_private(
                self.root / "recovery.json",
                {"observed_at": timestamp(), "queues": summary, "admission_restored": False},
            )

    def start(self, value, binding):
        with self.lock:
            if value["capsule_id"] in self.workers:
                raise ValueError("Observer identity already registered")
            if sum(w.thread.is_alive() for w in self.workers.values()) >= 4:
                raise RuntimeError("Concurrent observer budget reached")
            worker = ObserverWorker(self, value, binding)
            self.workers[value["capsule_id"]] = worker
            worker.thread.start()

    def finish(self, capsule_id):
        # Never wait for HTTP delivery while the application holds its store lock.
        with self.lock:
            worker = self.workers.get(capsule_id)
            if worker is not None:
                worker.stop.set()

    def status(self, capsule_id):
        with self.lock:
            worker = self.workers.get(capsule_id)
        if worker is None:
            return {"reasons": ["CONTINUOUS_OBSERVER_NOT_REGISTERED"], "sources": {}}
        return worker.snapshot()

    def review(self, value):
        status = self.status(value["capsule_id"])
        reasons = list(status["reasons"])
        if status.get("cgroup_inode") != value["identity"]["cgroup_inode"]:
            reasons.append("OBSERVER_WORKLOAD_IDENTITY_MISMATCH")
        return sorted(set(reasons))

    def shutdown(self):
        self.recovery_stop.set()
        with self.lock:
            workers = list(self.workers.values())
        for worker in workers:
            worker.stop.set()
        for worker in workers:
            worker.thread.join(timeout=40)
        if self.recovery_thread is not None:
            self.recovery_thread.join(timeout=20)
        if any(worker.thread.is_alive() for worker in workers):
            raise RuntimeError("Observer shutdown remains unverified")


class ObserverWorker:
    def __init__(self, supervisor, value, binding):
        self.supervisor, self.value, self.binding = supervisor, value, binding
        self.root = private_directory(supervisor.root / value["capsule_id"])
        self.epoch = uuid4().hex
        self.stop, self.lock = threading.Event(), threading.Lock()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.sources = {}
        self.processes, self.readers = {}, []
        self.queues = {}
        self.errors = {"OBSERVER_STARTUP_PENDING"}
        self.packet_health = None
        self.last_check = None
        self.policy = "agentguard-" + uuid4().hex
        self.policy_may_exist = False
        self.source_epoch = None
        self.previous_metrics = None
        self.metric_loss = None
        self.metric_reset = False
        self.last_wall, self.last_mono = time.time(), time.monotonic()
        self.clock_bad = False
        self.finished = False
        self.commands = {}
        self.restarts = {kind: 0 for kind in SOURCE_IDS}
        self.failure_counts = {kind: 0 for kind in SOURCE_IDS}
        self.health_file = self.root / "health.jsonl"
        self.workload = Workload(
            value["container_id"],
            binding.cgroup_id,
            binding.task_id,
            binding.contract_version,
            binding.capsule_id,
            binding.host_id,
            value["identity"]["process_start_observed_at"],
        )
        self.manifest = {
            "epoch": self.epoch,
            "binding": binding.model_dump(mode="json"),
            "workload": asdict(self.workload),
            "policy": self.policy,
            "initial_gap_start": self.workload.started_at,
        }
        self.write_private(self.root / "manifest.json", self.manifest)

    @staticmethod
    def write_private(path, value):
        temporary = path.with_suffix(".tmp")
        descriptor = os.open(
            temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    def snapshot(self):
        with self.lock:
            sources = dict(self.sources)
            reasons = set(self.errors)
            checked = self.last_check
        reasons.update(health_reasons(sources, time.monotonic()))
        if checked is None or time.monotonic() - checked > 5:
            reasons.add("SUPERVISOR_HEALTH_STALE")
        # These are actual unresolved capabilities of this implementation. An
        # empty queue, sampled zero counters or a live helper cannot remove them.
        reasons.update(
            {
                "BOOTSTRAP_OBSERVATION_START_GAP",
                "FILE_AND_NETWORK_HOOK_SCOPE_PARTIAL",
                "NETWORK_PROCESS_ATTRIBUTION_UNAVAILABLE",
                "SOURCE_CLOCK_SEMANTICS_UNVERIFIED",
            }
        )
        if self.finished:
            reasons.add("CONTINUOUS_OBSERVER_STOPPED")
        return {
            "epoch": self.epoch,
            "capsule_id": self.binding.capsule_id,
            "cgroup_inode": self.value["identity"]["cgroup_inode"],
            "sources": {key: asdict(source) for key, source in sources.items()},
            "reasons": sorted(reasons),
            "finished": self.finished,
            "restarts": dict(self.restarts),
            "protected_execution_ready": False,
        }

    def note(self, kind, code):
        with self.lock:
            if code not in self.errors:
                self.failure_counts[kind] += 1
            self.errors.add(code)

    def spawn(self, kind, args):
        self.commands[kind] = args
        if kind == "packet" and kind in self.processes:
            with self.lock:
                self.packet_health = None
        (self.root / (kind + ".jsonl")).touch(mode=0o600, exist_ok=True)
        with (self.root / (kind + ".stderr")).open("ab") as errors:
            process = subprocess.Popen(  # noqa: S603 - fixed trusted collectors
                args,
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=errors,
                start_new_session=True,
            )
        self.processes[kind] = process
        reader = threading.Thread(target=self.read_source, args=(kind, process), daemon=True)
        self.readers.append(reader)
        reader.start()

    def read_source(self, kind, process):
        try:
            with (self.root / (kind + ".jsonl")).open("ab", buffering=0) as journal:
                while not self.stop.is_set():
                    line = process.stdout.readline(65537)
                    if not line:
                        self.note(kind, kind.upper() + "_SOURCE_EOF")
                        return
                    if len(line) > 65536 or not line.endswith(b"\n"):
                        self.note(kind, kind.upper() + "_INVALID_SOURCE_FRAME")
                        return
                    raw = strict_json(line)
                    if kind == "packet":
                        if raw.get("kind") in {"ready", "health"}:
                            with self.lock:
                                self.packet_health = raw | {"received_monotonic": time.monotonic()}
                            with self.health_file.open("ab", buffering=0) as health:
                                health.write(line)
                                os.fsync(health.fileno())
                            continue
                        if raw.get("kind") != "packet":
                            self.note(kind, "PACKET_SOURCE_STOPPED")
                            return
                        if raw.get("capsule_id") != self.binding.capsule_id:
                            self.note(kind, "PACKET_SOURCE_IDENTITY_MISMATCH")
                            return
                        if raw.get("metadata", {}).get(
                            "packet_type"
                        ) != 4 or "destination_ip" not in raw.get("metadata", {}):
                            continue
                    else:
                        body = next(
                            (
                                raw[k]
                                for k in ("process_exec", "process_exit", "process_kprobe")
                                if k in raw
                            ),
                            {},
                        )
                        source = body.get("process", {})
                        docker = source.get("docker", "")
                        if not docker:
                            # UID 0 runtime setup is outside the unprivileged
                            # capsule scope. Potential agent records stay gaps.
                            if source.get("uid") == 65532:
                                self.note(kind, "HOST_SOURCE_ATTRIBUTION_GAP")
                            continue
                        if not self.value["container_id"].startswith(docker):
                            continue
                    if journal.tell() + len(line) > 16 * 1024 * 1024:
                        self.note(kind, kind.upper() + "_JOURNAL_QUOTA_REACHED")
                        return
                    journal.write(line)
                    os.fsync(journal.fileno())
        except Exception:
            self.note(kind, kind.upper() + "_SOURCE_READ_FAILED")

    def normalize(self, kind, line, reference):
        raw = strict_json(line)
        if kind == "packet":
            if (
                raw.get("capsule_id") != self.binding.capsule_id
                or type(raw.get("network_namespace_inode")) is not int
            ):
                raise ValueError("Packet journal attribution mismatch")
            metadata = raw["metadata"]
            if metadata.get("packet_type") != 4 or "destination_ip" not in metadata:
                raise ValueError("Not an attributable outgoing IP frame")
            value = SecurityEvent(
                event_id=hashlib.sha256(line).hexdigest(),
                task_id=self.binding.task_id,
                contract_version=self.binding.contract_version,
                capsule_id=self.binding.capsule_id,
                host_id=self.binding.host_id,
                source="network_sensor",
                event_type="egress_flow",
                observed_at=datetime.fromisoformat(raw["observed_at"]),
                # Namespace-level evidence has no genuine sender process birth.
                # Leave it absent: TERE must retain attribution uncertainty.
                process_identity=None,
                operation="packet_outgoing",
                resource_or_destination=metadata["destination_ip"],
                effect_status="observed",
                coverage_status="partial",
                evidence_reference="packet:" + hashlib.sha256(line).hexdigest(),
            )
            return value.model_dump(mode="json")
        normalizer = (
            TetragonNormalizer(SOURCE_IDS[kind], [self.workload])
            if kind == "process"
            else HookNormalizer(SOURCE_IDS[kind], [self.workload], [self.policy])
        )
        event, metadata = translate_member2_event(
            normalizer.normalize(raw, reference), SOURCE_IDS[kind]
        )
        delta = (event.observed_at - datetime.now(event.observed_at.tzinfo)).total_seconds()
        if delta > 5:
            self.note(kind, "SOURCE_TIME_AHEAD_OF_RECEIPT")
        elif delta < -5:
            self.note(kind, "SOURCE_EVENT_DELIVERY_DELAYED")
        return {
            "wire_format": "member2-normalized-1.0",
            "event": event.model_dump(mode="json")
            | {"received_at": metadata["collector_received_at"], "details": metadata["details"]},
        }

    def attest_health(self):
        wall, mono = time.time(), time.monotonic()
        if not clock_compatible(self.last_wall, self.last_mono, wall, mono):
            self.clock_bad = True
            self.note("process", "HOST_CLOCK_DISCONTINUITY")
        self.last_wall, self.last_mono = wall, mono
        try:
            info = json.loads(command(["docker", "inspect", "agentguard-tetragon"], timeout=3))[0]
            expected_image = json.loads((ROOT / "platform/versions.json").read_text())[
                "tetragon_image"
            ]
            if (
                info["Config"]["Image"] != expected_image
                or info["Config"]["Labels"].get("agentguard.component") != "host-sensor"
                or not info["State"]["Running"]
            ):
                raise ValueError("Managed sensor identity unavailable")
            epoch = (info["Id"], info["State"]["StartedAt"])
            if self.source_epoch is not None and epoch != self.source_epoch:
                self.metric_reset = True
                self.note("process", "HOST_SENSOR_EPOCH_CHANGED")
            self.source_epoch = epoch
            if (
                command(["docker", "exec", "agentguard-tetragon", "tetra", "status"], timeout=3)
                != "Health Status: running"
            ):
                raise ValueError("Source health unavailable")
            current = sensor_metrics()
            self.metric_loss, reset = metric_delta(self.previous_metrics or {}, current)
            self.metric_reset |= reset and self.previous_metrics is not None
            self.previous_metrics = current
            if self.metric_loss:
                self.note("process", "HOST_SENSOR_EVENT_LOSS")
            policies = json.loads(
                command(
                    ["docker", "exec", "agentguard-tetragon", "tetra", "tp", "list", "-o", "json"],
                    timeout=3,
                )
            )
            if not any(
                p.get("name") == self.policy and p.get("state") == "TP_STATE_ENABLED"
                for p in policies.get("policies", [])
            ):
                self.note("hooks", "HOOK_POLICY_NOT_ENABLED")
            last_host = time.monotonic()
        except Exception:
            self.note("process", "HOST_SENSOR_HEALTH_UNAVAILABLE")
            last_host = None
        # Revalidate the exact host workload without acquiring its runtime lock.
        identity = self.value["identity"]
        try:
            if process_identity(identity["pid"]) != {
                k: identity[k] for k in ("pid", "start_ticks", "cgroup")
            }:
                raise ValueError("Workload changed")
            cgroup = Path("/sys/fs/cgroup") / identity["cgroup"].lstrip("/")
            if cgroup.stat().st_ino != identity["cgroup_inode"]:
                raise ValueError("Cgroup replaced")
        except Exception:
            self.note("process", "OBSERVED_WORKLOAD_IDENTITY_UNAVAILABLE")
        with self.lock:
            packet = dict(self.packet_health or {})
            for kind, queue in self.queues.items():
                status = queue.status()
                process = self.processes.get(kind)
                is_packet = kind == "packet"
                heartbeat = packet.get("received_monotonic") if is_packet else last_host
                loss = packet.get("dropped") if is_packet else self.metric_loss
                gaps = (
                    status["gaps"]
                    + self.failure_counts[kind]
                    + (packet.get("parser_gaps", 0) if is_packet else 0)
                )
                self.sources[kind] = SourceHealth(
                    process is not None and process.poll() is None,
                    heartbeat,
                    status["pending"],
                    gaps,
                    loss,
                    status["export_failures"],
                    self.metric_reset if not is_packet else self.restarts[kind] > 0,
                )
            self.last_check = time.monotonic()

    def coverage(self, start, end):
        if parse_time(end) <= parse_time(start):
            return
        for kind, queue in self.queues.items():
            source = self.sources.get(kind)
            status = (
                ("unknown" if source.lost is None else "partial")
                if source is not None and source.alive
                else "unavailable"
            )
            event_classes = {
                "process": ("process_exec", "process_exit"),
                "hooks": ("file_access", "connection_attempt"),
                "packet": ("egress_flow",),
            }[kind]
            coverage = Coverage(
                coverage_id=uuid4().hex,
                task_id=self.binding.task_id,
                capsule_id=self.binding.capsule_id,
                sensor_id=SOURCE_IDS[kind],
                source="network_sensor" if kind == "packet" else "host_sensor",
                event_classes=event_classes,
                start=parse_time(start),
                end=parse_time(end),
                status=status,
                lost_events=source.lost or 0 if source else 0,
            )
            with queue.db:
                queue.enqueue(coverage.model_dump(mode="json"), endpoint="coverage")

    def run(self):
        start = self.workload.started_at
        try:
            for kind in SOURCE_IDS:
                self.queues[kind] = ExportQueue(
                    private_directory(self.root / (kind + "-queue")),
                    SOURCE_IDS[kind],
                    api_port=self.supervisor.port,
                )
            policy_file = self.root / "policy.json"
            self.write_private(
                policy_file,
                capsule_policy(self.policy, verified_mount_namespace(self.value)),
            )
            remote = "/etc/tetragon/" + self.policy + ".json"
            command(["docker", "cp", str(policy_file), "agentguard-tetragon:" + remote])
            self.policy_may_exist = True
            command(
                ["docker", "exec", "agentguard-tetragon", "tetra", "tp", "add", remote], timeout=30
            )
            if self.stop.is_set():
                return
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
            self.spawn(
                "process",
                common
                + [
                    "--event-types",
                    "PROCESS_EXEC,PROCESS_EXIT",
                    "--exclude-fields",
                    "process.arguments,parent.arguments",
                ],
            )
            self.spawn(
                "hooks",
                common
                + [
                    "--policy-names",
                    self.policy,
                    "--exclude-fields",
                    "process.arguments,parent.arguments",
                ],
            )
            self.spawn(
                "packet",
                [
                    sys.executable,
                    "-m",
                    "scripts.linux_packet_stream",
                    "--record",
                    str(self.supervisor.controller.record(self.binding.capsule_id).path),
                ],
            )
            with self.lock:
                self.errors.discard("OBSERVER_STARTUP_PENDING")
            while not self.stop.wait(0.5):
                for kind, process in list(self.processes.items()):
                    if process.poll() is not None:
                        if self.restarts[kind] < 3:
                            self.restarts[kind] += 1
                            self.note(kind, kind.upper() + "_SOURCE_RESTARTED")
                            self.spawn(kind, self.commands[kind])
                        else:
                            self.note(kind, kind.upper() + "_SOURCE_RESTART_BUDGET_EXCEEDED")
                for kind, queue in self.queues.items():
                    queue.tail(
                        self.root / (kind + ".jsonl"),
                        lambda line, ref, kind=kind: self.normalize(kind, line, ref),
                        endpoint="events" if kind == "packet" else "member2",
                    )
                    queue.drain(self.supervisor.sensors[SOURCE_IDS[kind]].token, max_frames=64)
                self.attest_health()
                end = timestamp()
                self.coverage(start, end)
                start = end
                snapshot = self.snapshot()
                snapshot["metrics"] = self.previous_metrics
                self.write_private(self.root / "status.json", snapshot)
                if time.monotonic() >= self.value["monotonic_deadline"]:
                    self.note("process", "OBSERVER_WORKLOAD_DEADLINE")
                    break
        except Exception:
            self.note("process", "CONTINUOUS_OBSERVER_FAILED")
        finally:
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
            try:
                for kind, queue in self.queues.items():
                    path = self.root / (kind + ".jsonl")
                    if path.exists():
                        queue.tail(
                            path,
                            lambda line, ref, kind=kind: self.normalize(kind, line, ref),
                            endpoint="events" if kind == "packet" else "member2",
                        )
                self.coverage(start, timestamp())
                for kind, queue in self.queues.items():
                    queue.drain(self.supervisor.sensors[SOURCE_IDS[kind]].token, max_frames=64)
            except Exception:
                self.note("process", "FINAL_OBSERVER_EXPORT_PENDING")
            for queue in self.queues.values():
                queue.close()
            if self.policy_may_exist:
                try:
                    command(
                        [
                            "docker",
                            "exec",
                            "agentguard-tetragon",
                            "tetra",
                            "tp",
                            "delete",
                            self.policy,
                        ],
                        timeout=5,
                    )
                except Exception:
                    self.note("hooks", "OBSERVER_POLICY_CLEANUP_UNVERIFIED")
            self.finished = True
            with self.lock:
                self.sources = {
                    kind: replace(source, alive=False) for kind, source in self.sources.items()
                }
            self.write_private(self.root / "status.json", self.snapshot())


class JournalReplay:
    """Reuse exactly the original normalizer for preserved private source frames."""

    def __init__(self, binding, workload, policy, queue):
        self.binding, self.workload, self.policy, self.queue = binding, workload, policy, queue

    def note(self, kind, code):
        self.queue.gap(code)

    normalize = ObserverWorker.normalize
