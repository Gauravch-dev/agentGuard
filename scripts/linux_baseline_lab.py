"""Measured synthetic probe baselines; not an admitted Finance efficacy result.

The host sensor's base process monitor stays on in every mode. Only the scoped
file/socket policy and namespace packet tap vary. Raw samples include Docker exec
overhead. No attack success rate, false-positive rate or production percentile is
derived from this small controlled experiment.
"""

import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.hook_policy import capsule_policy
from agentguard.platform import command
from agentguard.policy_control import install_policy, remove_policy
from agentguard.schema import timestamp
from agentguard.supervisor import verified_mount_namespace
from application.authority import Authority
from application.store import Store

ROOT = Path(__file__).resolve().parents[1]


def sample(controller, authority, root, image, mode, iteration):
    private = private_directory(root / (mode + "-" + str(iteration)))
    value = controller.prepare(authority.create("linux-lab-owner").model_dump(mode="json"))
    policy = "agentguard-" + uuid4().hex
    loaded = False
    helpers = []
    streams = []
    try:
        if mode == "combined_partial":
            path = private / "policy.json"
            path.write_text(
                json.dumps(capsule_policy(policy, verified_mount_namespace(value), expanded=True))
            )
            loaded = True
            install_policy(path, policy)
            raw, errors = (
                (private / "hooks.jsonl").open("xb"),
                (private / "hooks.stderr").open("xb"),
            )
            streams.extend((raw, errors))
            helpers.append(
                subprocess.Popen(  # noqa: S603 - fixed managed collector
                    [
                        "/usr/bin/docker",
                        "exec",
                        "agentguard-tetragon",
                        "timeout",
                        "-s",
                        "TERM",
                        "-k",
                        "2",
                        "20",
                        "tetra",
                        "getevents",
                        "--policy-names",
                        policy,
                        "--exclude-fields",
                        "process.arguments,parent.arguments",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=raw,
                    stderr=errors,
                    start_new_session=True,
                )
            )
            time.sleep(0.5)
        if mode != "probe_stdout_only":
            ready = private / "tap.ready"
            raw, errors = (
                (private / "packet.json").open("xb"),
                (private / "packet.stderr").open("xb"),
            )
            streams.extend((raw, errors))
            tap = subprocess.Popen(  # noqa: S603 - fixed trusted packet helper
                [
                    sys.executable,
                    "-m",
                    "scripts.linux_network_lab",
                    "--capture-record",
                    str(controller.record(value["capsule_id"]).path),
                    "--ready",
                    str(ready),
                ],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=raw,
                stderr=errors,
                start_new_session=True,
            )
            helpers.append(tap)
            deadline = time.monotonic() + 10
            while not ready.exists():
                if tap.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Baseline packet tap unavailable")
                time.sleep(0.05)
        probe = (ROOT / "platform/profiles/scope_probe.py").read_text()
        started = time.monotonic_ns()
        result = json.loads(
            command(
                [
                    "docker",
                    "exec",
                    "--user=65532:65532",
                    value["container_id"],
                    "python",
                    "-I",
                    "-c",
                    probe,
                ],
                timeout=20,
            )
        )
        elapsed = time.monotonic_ns() - started
        if mode != "probe_stdout_only":
            tap.wait(timeout=10)
            if tap.returncode:
                raise RuntimeError("Baseline packet capture failed")
        if mode == "combined_partial":
            time.sleep(1)
        packet = (
            json.loads((private / "packet.json").read_text())
            if mode != "probe_stdout_only"
            else None
        )
        hook_frames = []
        if loaded:
            for line in (private / "hooks.jsonl").read_bytes().splitlines():
                raw = json.loads(line)
                body = raw.get("process_kprobe", {})
                docker = body.get("process", {}).get("docker", "")
                if (
                    isinstance(docker, str)
                    and len(docker) >= 12
                    and value["container_id"].startswith(docker)
                ):
                    hook_frames.append(body)
        cleaned = controller.terminate(value["capsule_id"])
        return {
            "mode": mode,
            "iteration": iteration,
            "capsule_id": value["capsule_id"],
            "probe_exec_elapsed_ns": elapsed,
            "reported_probe_outcomes": {
                key: {k: v for k, v in item.items() if k != "elapsed_ns"}
                for key, item in result.items()
            },
            "independent_hook_frames": len(hook_frames),
            "independent_file_attempt_observed": any(
                "openat" in body.get("function_name", "")
                and any(arg.get("string_arg") == "/etc/shadow" for arg in body.get("args", []))
                for body in hook_frames
            ),
            "independent_connect_attempt_observed": any(
                "connect" in body.get("function_name", "") for body in hook_frames
            ),
            "outgoing_packet_metadata_frames": sum(
                item["packet_type"] == 4 for item in packet["packets"]
            )
            if packet
            else None,
            "kernel_packet_drops": packet["kernel_drops"] if packet else None,
            "finance_admitted": cleaned["admitted"],
            "cleanup_verified": cleaned["descendants_exited"] and cleaned["channel_revoked"],
        }
    finally:
        for process in helpers:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        for stream in streams:
            stream.close()
        controller.terminate(value["capsule_id"])
        if loaded:
            remove_policy(policy)


def run(image, iterations, output):
    if not 2 <= iterations <= 5:
        raise ValueError("Bounded baseline sample count of 2 to 5 required")
    os.umask(0o077)
    private = private_directory(Path("/var/lib/agentguard/baseline-lab") / uuid4().hex)
    store = Store(private / "evidence.sqlite3", os.urandom(32).hex())
    authority = Authority(store)
    controller = StagedCapsules(image, state_root=private / "runtime")
    samples = []
    try:
        for iteration in range(iterations):
            for mode in ("probe_stdout_only", "network_metadata_only", "combined_partial"):
                samples.append(sample(controller, authority, private, image, mode, iteration))
    finally:
        store.db.close()
    checks = {
        "all_samples_contained_without_finance_admission": all(
            row["cleanup_verified"] and not row["finance_admitted"] for row in samples
        ),
        "network_taps_observed_actual_loopback_traffic": all(
            row["outgoing_packet_metadata_frames"] > 0
            for row in samples
            if row["mode"] != "probe_stdout_only"
        ),
        "combined_hooks_observed_file_and_connect_attempts": all(
            row["independent_file_attempt_observed"] and row["independent_connect_attempt_observed"]
            for row in samples
            if row["mode"] == "combined_partial"
        ),
    }
    report = {
        "observed_at": timestamp(),
        "mode": "controlled-synthetic-probe-baselines",
        "image_id": image,
        "samples": samples,
        "checks": checks,
        "passed": all(checks.values()),
        "median_probe_exec_ns": {
            mode: statistics.median(
                row["probe_exec_elapsed_ns"] for row in samples if row["mode"] == mode
            )
            for mode in ("probe_stdout_only", "network_metadata_only", "combined_partial")
        },
        "limits": [
            "Supplemental probe baseline; application-log-only Finance baseline is blocked",
            "Base Tetragon process monitor remains on in all modes",
            "Elapsed exec includes Docker/client/Python startup; excludes observer policy setup and teardown",
            "Small raw samples, not production latency percentiles or attack-prevention rates",
            "Packet-only evidence has no originating process or blocked-attempt semantics",
            "Combined observer remains partial; no complete source coverage or protected output release",
        ],
        "full_S16_finance_comparison_complete": False,
        "protected_execution_ready": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("docs/linux/baseline_review.json"))
    args = parser.parse_args()
    report = run(args.image_id, args.iterations, args.output)
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "checks": report["checks"],
                "samples": len(report["samples"]),
                "median_probe_exec_ns": report["median_probe_exec_ns"],
            },
            indent=2,
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
