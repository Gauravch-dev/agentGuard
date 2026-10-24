# ruff: noqa: E402
"""Bounded genuine Docker + Tetragon process experiment on the owned Linux host.

Raw captures remain private on Linux. Public artifacts omit arguments and host names.
Process-only visibility never becomes a complete independent coverage assertion.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agentguard.authority import sample_contract
from agentguard.platform import DockerLab, command
from agentguard.schema import strict_json, timestamp
from agentguard.sensors import MappingError, TetragonNormalizer, Workload

COUNTERS = (
    "tetragon_observer_ringbuf_events_lost_total",
    "tetragon_observer_ringbuf_queue_events_lost_total",
    "tetragon_events_missing_process_info_total",
    "tetragon_events_export_failed_total",
)


def metrics_snapshot():
    counters = dict.fromkeys(COUNTERS)
    text = command(
        ["docker", "exec", "agentguard-tetragon", "wget", "-qO-", "http://127.0.0.1:2112/metrics"]
    )
    for line in text.splitlines():
        match = re.fullmatch(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{[^}]*\})?\s+([0-9]+(?:\.0+)?)", line)
        if match and match[1] in counters:
            counters[match[1]] = (counters[match[1]] or 0) + int(match[2].split(".")[0])
    return {
        "observed_at": timestamp(),
        "counters": counters,
        "scope": "actual Tetragon host-wide counters; missing families are null, never zero",
    }


def counter_deltas(before, after):
    result = {}
    for name in COUNTERS:
        low, high = before["counters"][name], after["counters"][name]
        result[name] = (
            {"delta": high - low, "status": "observed"}
            if low is not None and high is not None and high >= low
            else {"delta": None, "status": "unknown_or_reset"}
        )
    return result


def run(image: str, output: Path) -> dict:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run on the trusted rootful Linux lab host")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("reviewed local immutable image ID required")
    run_id = uuid4().hex
    private = Path("/var/lib/agentguard/evidence") / run_id
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    health_before = command(["docker", "exec", "agentguard-tetragon", "tetra", "status"])
    if health_before != "Health Status: running":
        raise RuntimeError("sensor did not report running")
    metrics_before = metrics_snapshot()
    started = timestamp()
    raw_path = private / "process.jsonl"
    errors_path = private / "subscription.stderr"
    with raw_path.open("xb") as raw, errors_path.open("xb") as errors:
        raw_path.chmod(0o600)
        errors_path.chmod(0o600)
        subscription = subprocess.Popen(
            [
                "/usr/bin/docker",
                "exec",
                "agentguard-tetragon",
                "/usr/bin/timeout",
                "-s",
                "TERM",
                "-k",
                "2",
                "15",
                "/usr/bin/tetra",
                "getevents",
                "--process",
                "^/usr/local/bin/python.*$",
                "--exclude-fields",
                "process.arguments,parent.arguments",
            ],
            stdout=raw,
            stderr=errors,
        )
        time.sleep(0.3)
        if subscription.poll() is not None:
            raise RuntimeError("sensor subscription failed before lab start")
        try:
            lab = DockerLab().isolation_lab(sample_contract("LINUX-LAB-001"), image)
        finally:
            try:
                subscription.wait(timeout=20)
            except subprocess.TimeoutExpired:
                subscription.kill()
                subscription.wait(timeout=3)
                raise RuntimeError("bounded sensor subscription did not terminate") from None
    ended = timestamp()
    workload = Workload(
        lab["container_id"],
        "cg-" + str(lab["runtime_identity"]["cgroup_inode"]),
        "LINUX-LAB-001",
        1,
        lab["capsule_id"],
        "linux-lab-01",
        started,
        ended,
    )
    normalizer = TetragonNormalizer("linux-process-01", [workload])
    matched, failures, raw_count = [], [], 0
    for line in raw_path.read_text().splitlines():
        if len(line.encode()) > 65536:
            failures.append("oversize_sensor_record")
            continue
        value = strict_json(line)
        raw_count += 1
        kind = next((k for k in ("process_exec", "process_exit") if k in value), None)
        if not kind:
            continue
        source_container = value[kind].get("process", {}).get("docker", "")
        if not source_container or not lab["container_id"].startswith(source_container):
            continue
        reference = "tetragon:" + hashlib.sha256(line.encode()).hexdigest()
        try:
            normalized = normalizer.normalize(value, reference)
            # Parent exec IDs may embed a host name. Keep raw lineage in the private
            # capture; omit it from committed, sanitized evidence rather than invent it.
            normalized["details"].pop("parent_exec_id", None)
            matched.append(normalized)
        except MappingError as exc:
            failures.append(
                {
                    "reason": str(exc),
                    "event_type": kind,
                    "observed_at": value.get("time"),
                    "source_process_start": value[kind]["process"].get("start_time"),
                    "evidence_reference": reference,
                }
            )
    health_after = command(["docker", "exec", "agentguard-tetragon", "tetra", "status"])
    metrics_after = metrics_snapshot()
    if not matched:
        failures.append("no_attributable_process_event_captured")
    report = {
        "observed_at": ended,
        "execution_mode": "real-linux-isolation-lab",
        "lab": lab,
        "source": "actual Tetragon eBPF process stream, not agent logs",
        "sensor_health_before": health_before,
        "sensor_health_after": health_after,
        "metrics_before": metrics_before,
        "metrics_after": metrics_after,
        "counter_deltas": counter_deltas(metrics_before, metrics_after),
        "subscription_exit_code": subscription.returncode,
        "raw_records": raw_count,
        "attributed_process_events": matched,
        "normalization_gaps": failures,
        "coverage_status": "partial" if matched else "unavailable",
        "process_observation_verified": bool(matched),
        "coverage_scope": ["configured process_exec", "configured process_exit"],
        "missing_required_scopes": [
            "file_access",
            "connection_attempt",
            "egress_flow",
            "continuous_loss_accounting",
        ],
        "protected_execution_ready": False,
        "private_raw_reference": "operator-retained-linux-evidence:" + run_id,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {
        "lab_passed": lab["probes"]["passed"],
        "process_events": len(matched),
        "normalization_gaps": failures,
        "protected_execution_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/linux/live_lab.json")
    args = parser.parse_args()
    result = run(args.image_id, args.output)
    print(json.dumps(result, indent=2))
    return 0 if result["process_events"] and not result["normalization_gaps"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
