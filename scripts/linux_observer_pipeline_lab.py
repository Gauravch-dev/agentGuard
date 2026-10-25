"""Real kernel capture -> durable exporter -> authenticated application evidence.

Finance admission stays held. A trusted docker-exec probe supplies a denied file
attempt. Neither capture EOF nor successful delivery asserts complete coverage.
"""

import argparse
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import httpx

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.export_queue import ExportQueue
from agentguard.hook_policy import HookNormalizer, capsule_policy
from agentguard.platform import command
from agentguard.sensors import Workload
from application.member2_bridge import translate_member2_event
from application.models import now
from application.store import Store
from scripts.linux_lifecycle_lab import configuration, launch_server
from scripts.linux_sensor_registry import create

ROOT = Path(__file__).resolve().parents[1]


def run(image, output):
    os.umask(0o077)
    private = private_directory(Path("/var/lib/agentguard/pipeline-lab") / uuid4().hex)
    create(private, "linux-lab-01")
    settings = configuration(private)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = launch_server(private, image, port)
    controller = StagedCapsules(image, state_root=private / "runtime")
    capsule, policy, subscription, queue = None, None, None, None
    try:
        with httpx.Client(
            base_url=f"http://127.0.0.1:{port}",
            trust_env=False,
            follow_redirects=False,
            headers={"Authorization": "Bearer " + settings.owner_token},
            timeout=40,
        ) as client:
            response = client.post("/api/v1/tasks", json={})
            response.raise_for_status()
            task = response.json()["contract"]["task_id"]
            response = client.post(f"/api/v1/tasks/{task}/launch", json={})
            response.raise_for_status()
            binding = response.json()["binding"]
            capsule = binding["capsule_id"]
            record = controller.inspect(capsule)
            policy = "agentguard-" + uuid4().hex
            source_policy = private / "policy.json"
            source_policy.write_text(
                json.dumps(
                    capsule_policy(
                        policy,
                        Path(f"/proc/{record['identity']['pid']}/ns/mnt").stat().st_ino,
                    )
                )
            )
            remote = "/etc/tetragon/" + policy + ".json"
            command(["docker", "cp", str(source_policy), "agentguard-tetragon:" + remote])
            command(
                ["docker", "exec", "agentguard-tetragon", "tetra", "tp", "add", remote], timeout=60
            )
            raw_path = private / "source.jsonl"
            with raw_path.open("xb") as raw, (private / "source.stderr").open("xb") as errors:
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
                        "5",
                        "tetra",
                        "getevents",
                        "--policy-names",
                        policy,
                        "--exclude-fields",
                        "process.arguments,parent.arguments",
                    ],
                    stdout=raw,
                    stderr=errors,
                )
                time.sleep(0.5)
                command(
                    [
                        "docker",
                        "exec",
                        "--user=65532:65532",
                        record["container_id"],
                        "python",
                        "-I",
                        "-c",
                        "try:\n open('/etc/shadow')\nexcept OSError:\n pass",
                    ]
                )
                subscription.wait(timeout=10)
            workload = Workload(
                record["container_id"],
                binding["cgroup_id"],
                task,
                binding["contract_version"],
                capsule,
                binding["host_id"],
                record["identity"]["process_start_observed_at"],
            )
            sensor_id = "linux-hooks-01"
            normalizer = HookNormalizer(sensor_id, [workload], [policy])

            def normalize(line, reference):
                shared, metadata = translate_member2_event(
                    normalizer.normalize(json.loads(line), reference), sensor_id
                )
                return {
                    "wire_format": "member2-normalized-1.0",
                    "event": shared.model_dump(mode="json")
                    | {
                        "received_at": metadata["collector_received_at"],
                        "details": metadata["details"],
                    },
                }

            queue = ExportQueue(private / "queue", sensor_id, api_port=port)
            while queue.tail(raw_path, normalize):
                pass
            before = queue.status()
            # A real wrong credential cannot deliver or delete queued evidence.
            queue.drain(settings.owner_token)
            wrong = queue.status()
            queue.close()
            queue = ExportQueue(private / "queue", sensor_id, api_port=port)
            replayed = queue.tail(raw_path, normalize)
            while queue.drain(settings.sensors[sensor_id].token):
                pass
            delivered = queue.status()
            events_response = client.get(f"/api/v1/tasks/{task}/events")
            events_response.raise_for_status()
            held = client.post(f"/api/v1/tasks/{task}/admit", json={})
            held.raise_for_status()
            terminated = client.post(f"/api/v1/tasks/{task}/terminate", json={})
            terminated.raise_for_status()
            checks = {
                "genuine_hook_events_queued": before["pending"] > 0,
                "owner_credential_rejected_for_sensor_delivery": wrong["pending"]
                == before["pending"]
                and wrong["export_failures"] > 0,
                "restart_preserved_checkpoint": replayed == 0,
                "registered_hook_credential_delivered_all_pending": delivered["pending"] == 0
                and delivered["delivered"] == before["pending"],
                "no_coverage_promotion": not delivered["coverage_promoted"],
                "admission_still_held": held.json()["agent_admitted"] is False,
                "verified_cleanup": terminated.json()["descendants_exited"]
                and terminated.json()["channel_revoked"],
            }
        server.terminate()
        server.wait(timeout=20)
        store = Store(settings.database, settings.integrity_key)
        try:
            persisted = store.evidence(task, "event")
            checks["real_events_persisted_under_distinct_hook_identity"] = len(
                persisted
            ) == delivered["delivered"] and all(
                r["body"]["sensor_id"] == sensor_id for r in persisted
            )
            checks["source_metadata_and_server_receipt_separate"] = len(
                store.evidence(task, "member2_metadata")
            ) == len(persisted)
            checks["evidence_integrity_valid"] = store.verify_chain()
            checks["no_agent_broker_or_report_action"] = not store.evidence(
                task, "broker"
            ) and not store.evidence(task, "report")
        finally:
            store.db.close()
        report = {
            "observed_at": now().isoformat(),
            "mode": "real-linux-observer-api-pipeline",
            "image_id": image,
            "task_id": task,
            "capsule_id": capsule,
            "checks": checks,
            "passed": all(checks.values()),
            "queue_before": before,
            "queue_after_wrong_credential": wrong,
            "queue_after_restart_and_delivery": delivered,
            "admission_hold_reasons": held.json()["reasons"],
            "coverage_status": "partial",
            "protected_execution_ready": False,
            "model_invoked": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        if queue is not None:
            queue.close()
        if subscription is not None and subscription.poll() is None:
            subscription.terminate()
            subscription.wait(timeout=10)
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=20)
        if capsule is not None:
            controller.terminate(capsule)
        if policy is not None:
            command(["docker", "exec", "agentguard-tetragon", "tetra", "tp", "delete", policy])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/linux/observer_pipeline.json")
    args = parser.parse_args()
    result = run(args.image_id, args.output)
    print(json.dumps({"passed": result["passed"], "checks": result["checks"]}, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
