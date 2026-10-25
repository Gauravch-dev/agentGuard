"""Bounded real namespace-scoped Tetragon syscall observation experiment.

No Finance admission or complete-coverage claim. Attempts target TEST-NET IPs
from network=none capsules, with no corporate data or external model calls.
"""

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.hook_policy import capsule_policy
from agentguard.platform import command
from agentguard.policy_control import install_policy, remove_policy
from application.authority import Authority
from application.models import now
from application.store import Store
from scripts.linux_live_lab import counter_deltas, metrics_snapshot

ROOT = Path(__file__).resolve().parents[1]


def run(image, output):
    os.umask(0o077)
    run_id = uuid4().hex
    private = private_directory(Path("/var/lib/agentguard/hook-lab") / run_id)
    controller = StagedCapsules(image, state_root=private / "runtime")
    store = Store(private / "evidence.sqlite3", os.urandom(32).hex())
    contract = Authority(store).create("linux-lab-owner", "HOOK-" + run_id)
    value = controller.prepare(contract.model_dump(mode="json"))
    name = "agentguard-" + run_id
    loaded = False
    subscription = None
    try:
        pid = value["identity"]["pid"]
        namespace = Path(f"/proc/{pid}/ns/mnt").stat().st_ino
        policy = capsule_policy(name, namespace)
        policy_file = private / "policy.json"
        policy_file.write_text(json.dumps(policy))
        loaded = True
        install_policy(policy_file, name)
        policy_status = json.loads(
            command(
                [
                    "docker",
                    "exec",
                    "agentguard-tetragon",
                    "tetra",
                    "tp",
                    "list",
                    "-o",
                    "json",
                ]
            )
        )
        before = metrics_snapshot()
        raw_path = private / "hooks.jsonl"
        with raw_path.open("xb") as raw, (private / "subscription.stderr").open("xb") as errors:
            subscription = subprocess.Popen(  # noqa: S603 - fixed managed sensor
                [
                    "/usr/bin/docker",
                    "exec",
                    "agentguard-tetragon",
                    "timeout",
                    "-s",
                    "TERM",
                    "-k",
                    "2",
                    "10",
                    "tetra",
                    "getevents",
                    "--policy-names",
                    name,
                    "--exclude-fields",
                    "process.arguments,parent.arguments",
                ],
                stdout=raw,
                stderr=errors,
            )
            time.sleep(0.5)
            if subscription.poll() is not None:
                raise RuntimeError("Hook subscription failed before probes")
            probe = """
import json,socket,subprocess,sys
r={}
for key,path in [('read_denied','/etc/shadow'),('write_denied','/etc/agentguard-lab-write')]:
 try:
  with open(path,'w' if key=='write_denied' else 'r'): pass
  r[key]=False
 except OSError as e: r[key]={'errno':e.errno}
for key,family,kind,target in [
 ('tcp_ipv4',socket.AF_INET,socket.SOCK_STREAM,('192.0.2.1',443)),
 ('udp_dns',socket.AF_INET,socket.SOCK_DGRAM,('192.0.2.53',53)),
 ('udp_ipv6',socket.AF_INET6,socket.SOCK_DGRAM,('2001:db8::1',53))]:
 s=socket.socket(family,kind); s.settimeout(0.5)
 try:
  s.connect(target) if kind==socket.SOCK_STREAM else s.sendto(b'agentguard-synthetic',target)
  r[key]={'completed':True}
 except OSError as e: r[key]={'errno':e.errno}
 finally: s.close()
subprocess.run([sys.executable,'-I','-c',"import socket; s=socket.socket(); s.settimeout(.5); s.connect(('192.0.2.2',443))"],capture_output=True)
print(json.dumps(r))
"""
            probe_result = json.loads(
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
                    ]
                )
            )
            subscription.wait(timeout=15)
        after = metrics_snapshot()
        events = []
        gaps = []
        for line in raw_path.read_text().splitlines():
            raw = json.loads(line)
            body = raw.get("process_kprobe", {})
            process = body.get("process", {})
            docker = process.get("docker", "")
            if not docker or not value["container_id"].startswith(docker):
                gaps.append("missing_or_foreign_container_identity")
                continue
            events.append(
                {
                    "observed_at": raw.get("time"),
                    "process_start": process.get("start_time"),
                    "pid": process.get("pid"),
                    "binary": process.get("binary"),
                    "function_name": body.get("function_name"),
                    "args": body.get("args"),
                    "return": body.get("return"),
                    "evidence_reference": "tetragon:" + hashlib.sha256(line.encode()).hexdigest(),
                }
            )
        functions = {event["function_name"] for event in events}
        # Runtime setup can briefly enter this namespace without a sensor Docker
        # identity. Keep these records as gaps; never assign them to the capsule.
        checks = {
            "namespace_scoped_policy_loaded": loaded,
            "file_syscall_observed": any("openat" in f for f in functions),
            "connect_syscall_observed": any("connect" in f for f in functions),
            "udp_sendto_observed": any("sendto" in f for f in functions),
            "actual_file_read_refused": bool(probe_result["read_denied"]),
            "actual_file_write_refused": bool(probe_result["write_denied"]),
            "actual_ipv4_tcp_refused": "errno" in probe_result["tcp_ipv4"],
            "actual_udp_dns_refused": "errno" in probe_result["udp_dns"],
            "actual_ipv6_udp_refused": "errno" in probe_result["udp_ipv6"],
            "unmatched_records_retained_as_gaps": len(events) + len(gaps)
            == len(raw_path.read_text().splitlines()),
            "finance_agent_not_admitted": not controller.inspect(value["capsule_id"])["admitted"],
        }
        report = {
            "observed_at": now().isoformat(),
            "mode": "real-linux-syscall-hook-lab",
            "image_id": image,
            "capsule_id": value["capsule_id"],
            "container_id": value["container_id"],
            "mount_namespace_inode": namespace,
            "cgroup_inode": value["identity"]["cgroup_inode"],
            "policy_sha256": hashlib.sha256(policy_file.read_bytes()).hexdigest(),
            "policy_status": policy_status,
            "probe_results": probe_result,
            "event_count": len(events),
            "events": [
                event
                for index, event in enumerate(events)
                if not any(
                    prior["function_name"] == event["function_name"]
                    and prior["args"] == event["args"]
                    for prior in events[:index]
                )
            ][:40],
            "gaps": gaps,
            "checks": checks,
            "passed": all(checks.values()),
            "metrics_before": before,
            "metrics_after": after,
            "counter_deltas": counter_deltas(before, after),
            "coverage_status": "partial",
            "protected_execution_ready": False,
            "private_raw_reference": "operator-retained-linux-hooks:" + run_id,
            "limitations": [
                "Bounded subscription, not continuous coverage",
                "Hooks cover only listed syscalls; not every file or networking mechanism",
                "Syscall failure is observed, not attributed to a specific enforcement control",
                "No packet/flow observation is inferred from a connection attempt",
            ],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        if subscription is not None and subscription.poll() is None:
            subscription.terminate()
            subscription.wait(timeout=15)
        controller.terminate(value["capsule_id"])
        if loaded:
            remove_policy(name)
        store.db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/linux/hook_lab.json")
    args = parser.parse_args()
    result = run(args.image_id, args.output)
    print(
        json.dumps(
            {
                "passed": result["passed"],
                "checks": result["checks"],
                "events": len(result["events"]),
            },
            indent=2,
        )
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
