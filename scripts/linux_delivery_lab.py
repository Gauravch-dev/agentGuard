"""Real Linux verification of the final owner views and safe delivery hold.

This supplements, and does not replace or weaken, the positive Finance/process
acceptance experiments. No fixture coverage, source identity or reviewer is used.
"""

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import time
from pathlib import Path
from uuid import uuid4

import httpx

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.platform import command
from agentguard.schema import timestamp
from agentguard.sensors import MappingError, TetragonNormalizer, Workload
from agentguard.source_time import nanoseconds
from application.store import Store
from scripts.linux_continuous_lab import await_value
from scripts.linux_lifecycle_lab import configuration, launch_server
from scripts.linux_sensor_registry import create


def request(client, method, path, **kwargs):
    response = client.request(method, path, **kwargs)
    response.raise_for_status()
    return response.json()


def run(image, digest, output):
    os.umask(0o077)
    private = private_directory(Path("/var/lib/agentguard/delivery-lab") / uuid4().hex)
    create(private, "linux-lab-01")
    settings = configuration(private, digest)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = launch_server(private, image, port, continuous=True, model_digest=digest)
    controller = StagedCapsules(image, state_root=private / "runtime")
    capsules, checks, timings, source_facts = [], {}, {}, []
    retired_delivery = {}
    try:
        with httpx.Client(
            base_url=f"http://127.0.0.1:{port}",
            trust_env=False,
            follow_redirects=False,
            timeout=90,
            headers={"Authorization": "Bearer " + settings.owner_token},
        ) as client:
            task = request(client, "POST", "/api/v1/tasks", json={})["contract"]["task_id"]
            base = f"/api/v1/tasks/{task}"
            started = time.monotonic()
            launched = request(client, "POST", base + "/launch", json={})
            timings["launch_with_prebirth_seconds"] = time.monotonic() - started
            binding = launched["binding"]
            capsule = binding["capsule_id"]
            capsules.append(capsule)
            value = controller.inspect(capsule)
            directory = private / "observers" / capsule

            def status():
                path = directory / "status.json"
                return json.loads(path.read_text()) if path.exists() else {}

            initial = await_value(
                status,
                lambda s: set(s.get("sources", {})) == {"process", "hooks", "packet"},
                seconds=35,
            )
            prebirth = json.loads((directory / "prebirth.json").read_text())
            checks["actual_subscriptions_witnessed_before_bootstrap_start"] = (
                prebirth["process_subscription_witnessed"]
                and prebirth["hook_subscription_witnessed"]
                and nanoseconds(prebirth["prepared_at"])
                < nanoseconds(value["identity"]["process_start_observed_at"])
            )
            posture = request(client, "GET", base + "/posture?version=1")
            checks["new_posture_reads_real_current_supervisor"] = posture["observer"][
                "connected"
            ] and set(posture["observer"]["sources"]) == {"process", "hooks", "packet"}
            checks["posture_excludes_private_runtime_paths_and_credentials"] = not any(
                secret in json.dumps(posture)
                for secret in (
                    "/var/lib/",
                    "/run/agentguard/",
                    settings.owner_token,
                    settings.runtime_token,
                    settings.integrity_key,
                )
            )
            checks["unknown_source_loss_remains_unknown"] = any(
                source["lost"] is None for source in posture["observer"]["sources"].values()
            )
            held = request(client, "POST", base + "/admit", json={})
            checks["mandatory_admission_gates_remain_held"] = not held["agent_admitted"] and bool(
                held["reasons"]
            )
            note = "Synthetic Linux review: monitoring limits hold Finance admission. No report has been released."
            request(client, "POST", base + "/notes?version=1", json={"text": note})
            probe = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); print(s.sendto(b'agentguard-synthetic',('127.0.0.1',49222))); s.close()"
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

            # Only require this negative smoke test's actual partial evidence.
            # Full positive process_exec/Finance checks remain separate and held.
            def evidence():
                return request(client, "GET", base + "/events?version=1")

            rows = await_value(
                evidence,
                lambda rs: any(
                    r["kind"] == "event" and r["body"]["event"]["source"] == "network_sensor"
                    for r in rs
                ),
                seconds=30,
            )
            checks["genuine_packet_observation_not_given_a_fabricated_sender"] = all(
                r["body"]["event"]["process_identity"] is None
                for r in rows
                if r["kind"] == "event" and r["body"]["event"]["source"] == "network_sensor"
            )
            newest = request(client, "GET", base + "/events?version=1&limit=10")
            older = request(
                client, "GET", base + f"/events?version=1&limit=10&before={newest[0]['sequence']}"
            )
            checks["actual_owner_evidence_paging_is_disjoint_and_ordered"] = bool(older) and max(
                row["sequence"] for row in older
            ) < min(row["sequence"] for row in newest)
            stopped = request(client, "POST", base + "/terminate", json={})
            final_status = await_value(status, lambda s: s.get("finished") is True, seconds=40)
            checks["real_cancellation_and_channel_revocation_verified"] = (
                stopped["descendants_exited"] and stopped["channel_revoked"]
            )
            checks["final_observer_drain_signalled_and_stopped"] = final_status["finished"]
            queue_path = directory / "hooks-queue" / "export.sqlite3"
            with sqlite3.connect(queue_path) as database:
                pending = database.execute(
                    "SELECT seq,payload FROM frames WHERE delivered=0 ORDER BY seq LIMIT 1"
                ).fetchone()
            if pending is not None:

                def delivered_frame():
                    with sqlite3.connect(queue_path) as database:
                        return database.execute(
                            "SELECT delivered,payload FROM frames WHERE seq=?", (pending[0],)
                        ).fetchone()

                try:
                    recovered = await_value(delivered_frame, lambda row: row[0] == 1, seconds=30)
                    resumed = recovered[1] == pending[1]
                except RuntimeError:
                    resumed = False
                checks["finished_worker_backlog_retries_without_service_restart"] = resumed
                retired_delivery = {
                    "naturally_pending_frame": True,
                    "payload_sha256": hashlib.sha256(pending[1].encode()).hexdigest(),
                    "unchanged_payload_acknowledged_without_restart": resumed,
                }
            else:
                retired_delivery = {
                    "naturally_pending_frame": False,
                    "observation": "No backlog at final sampling; no replay result claimed",
                }
            # Preserve the exact contradictory source timestamps and raw reference;
            # they are never repaired into successful process_exec observations.
            workload = Workload(
                value["container_id"],
                binding["cgroup_id"],
                task,
                1,
                capsule,
                "linux-lab-01",
                value["identity"]["process_start_observed_at"],
            )
            normalizer = TetragonNormalizer("linux-process-01", [workload])
            for line in (directory / "process.jsonl").read_bytes().splitlines():
                raw = json.loads(line)
                if "process_exec" not in raw:
                    continue
                reference = "tetragon:" + hashlib.sha256(line).hexdigest()
                try:
                    normalizer.normalize(raw, reference)
                    accepted = True
                except MappingError:
                    accepted = False
                source = raw["process_exec"]["process"]
                source_facts.append(
                    {
                        "observed_at": raw["time"],
                        "process_start": source["start_time"],
                        "evidence_reference": reference,
                        "accepted": accepted,
                    }
                )
            checks["actual_bootstrap_exec_record_retained"] = bool(source_facts)
            checks["uncertain_source_exec_never_becomes_complete_coverage"] = not any(
                r["body"]["status"] == "complete" for r in evidence() if r["kind"] == "coverage"
            )
            revision = request(client, "POST", base + "/revisions", json={})
            historical = request(client, "GET", base + "?version=1")
            historical_posture = request(client, "GET", base + "/posture?version=1")
            historical_notes = request(client, "GET", base + "/notes?version=1")
            current_notes = request(client, "GET", base + "/notes?version=2")
            checks["historical_views_cannot_restore_current_execution"] = (
                revision["contract"]["contract_version"] == 2
                and historical["is_current"] is False
                and not historical_posture["observer"]["connected"]
            )
            checks["actual_review_notes_stay_revision_scoped"] = (
                any(row["body"]["text"] == note for row in historical_notes) and current_notes == []
            )
            rows = request(client, "GET", base + "/events")
            checks["no_agent_admission_broker_action_or_report_created"] = not any(
                row["kind"] in {"admission", "broker", "report"} for row in rows
            )
        server.terminate()
        server.wait(timeout=50)
        ledger = Store(settings.database, settings.integrity_key)
        try:
            checks["actual_evidence_integrity_verified"] = ledger.verify_chain()
        finally:
            ledger.db.close()
        report = {
            "observed_at": timestamp(),
            "mode": "real-linux-owner-views-and-delivery-hold",
            "task_id": task,
            "capsule_id": capsule,
            "image_id": image,
            "checks": checks,
            "passed": all(checks.values()),
            "timings": timings,
            "prebirth": prebirth,
            "source_exec_observations": source_facts,
            "posture": posture,
            "admission_hold_reasons": held["reasons"],
            "initial_sources": initial["sources"],
            "final_sources": final_status["sources"],
            "retired_delivery": retired_delivery,
            "delivery_complete": False,
            "protected_finance_acceptance": "blocked",
            "recording": "Full admitted Finance demo blocked by mandatory source-coverage gates",
            "private_evidence_reference": "operator-retained-delivery:" + private.name,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=50)
            except TimeoutError:
                server.kill()
                server.wait(timeout=10)
        for capsule in capsules:
            controller.terminate(capsule)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--approved-model-digest", required=True)
    parser.add_argument("--output", type=Path, default=Path("docs/linux/delivery_review.json"))
    args = parser.parse_args()
    report = run(args.image_id, args.approved_model_digest, args.output)
    print(
        json.dumps(
            {"passed": report["passed"], "checks": report["checks"], "delivery_complete": False},
            indent=2,
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
