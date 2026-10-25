"""Real continuous observer delivery, packet-helper restart and API conflict checks.

Finance stays unadmitted. Explicitly labelled altered replays are negative protocol
inputs, not fabricated telemetry: the API must reject and retain their conflict.
"""

import argparse
import copy
import json
import os
import signal
import socket
import sqlite3
import time
from pathlib import Path
from uuid import uuid4

import httpx

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.platform import command
from application.models import now
from application.store import Store
from scripts.linux_lifecycle_lab import configuration, launch_server
from scripts.linux_sensor_registry import create

ROOT = Path(__file__).resolve().parents[1]


def await_value(read, predicate, *, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = read()
        if predicate(value):
            return value
        time.sleep(0.2)
    raise RuntimeError("Live observer condition not established within the bounded lab window")


def run(image, digest, output):
    os.umask(0o077)
    private = private_directory(Path("/var/lib/agentguard/continuous-lab") / uuid4().hex)
    create(private, "linux-lab-01")
    settings = configuration(private, digest)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = launch_server(private, image, port, continuous=True, model_digest=digest)
    controller = StagedCapsules(image, state_root=private / "runtime")
    capsules = []
    snapshots = {}
    try:
        with httpx.Client(
            base_url=f"http://127.0.0.1:{port}",
            trust_env=False,
            follow_redirects=False,
            timeout=40,
            headers={"Authorization": "Bearer " + settings.owner_token},
        ) as client:

            def post(path):
                response = client.post(path, json={})
                response.raise_for_status()
                return response.json()

            task = post("/api/v1/tasks")["contract"]["task_id"]
            binding = post(f"/api/v1/tasks/{task}/launch")["binding"]
            capsule = binding["capsule_id"]
            capsules.append(capsule)
            status_file = private / "observers" / capsule / "status.json"

            def status():
                return json.loads(status_file.read_text()) if status_file.exists() else {}

            def evidence():
                response = client.get(f"/api/v1/tasks/{task}/events")
                response.raise_for_status()
                return response.json()

            snapshots["initial"] = await_value(
                status, lambda s: set(s.get("sources", {})) == {"process", "hooks", "packet"}
            )
            record = controller.inspect(capsule)
            probe = """
import socket,subprocess,sys
try: open('/etc/shadow')
except OSError: pass
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'agentguard-synthetic',('127.0.0.1',49191)); s.close()
subprocess.run([sys.executable,'-I','-c',"import socket; s=socket.socket(); s.settimeout(.2); s.connect(('192.0.2.1',443))"],capture_output=True)
"""

            def probe_once():
                command(
                    [
                        "docker",
                        "exec",
                        "--user=65532:65532",
                        record["container_id"],
                        "python",
                        "-I",
                        "-c",
                        probe,
                    ]
                )

            probe_once()
            rows = await_value(
                evidence,
                lambda rows: (
                    {"process_exec", "file_access", "connection_attempt", "egress_flow"}
                    <= {r["body"]["event"]["event_type"] for r in rows if r["kind"] == "event"}
                ),
            )
            event_types = {r["body"]["event"]["event_type"] for r in rows if r["kind"] == "event"}
            packet_before = sum(
                r["kind"] == "event" and r["body"]["event"]["source"] == "network_sensor"
                for r in rows
            )
            await_value(
                evidence,
                lambda rows: (
                    {"host_sensor", "network_sensor"}
                    <= {r["body"]["source"] for r in rows if r["kind"] == "coverage"}
                ),
            )
            # Identify only this lab's exact packet helper by its full record
            # argument; no unrelated process or sensor service is interrupted.
            expected = [
                os.fsencode(os.sys.executable),
                b"-m",
                b"scripts.linux_packet_stream",
                b"--record",
                os.fsencode(controller.record(capsule).path),
            ]
            matches = []
            for path in Path("/proc").glob("[0-9]*/cmdline"):
                try:
                    if path.read_bytes().rstrip(b"\0").split(b"\0") == expected:
                        matches.append(int(path.parent.name))
                except OSError:
                    continue
            if len(matches) != 1:
                raise RuntimeError("Exact lab packet helper identity not unique")
            os.kill(matches[0], signal.SIGTERM)
            snapshots["after_restart"] = await_value(
                status,
                lambda s: (
                    s.get("restarts", {}).get("packet", 0) > 0
                    and s.get("sources", {}).get("packet", {}).get("alive") is True
                ),
            )
            probe_once()
            rows = await_value(
                evidence,
                lambda rs: (
                    sum(
                        r["kind"] == "event" and r["body"]["event"]["source"] == "network_sensor"
                        for r in rs
                    )
                    > packet_before
                ),
            )
            before_conflict = post(f"/api/v1/tasks/{task}/admit")
            metadata = next(
                r
                for r in rows
                if r["kind"] == "member2_metadata" and r["body"]["details"].get("hook_policy")
            )
            original = next(
                r["body"]["event"]
                for r in rows
                if r["kind"] == "event" and r["identity"] == metadata["identity"]
            )
            envelope = {
                "wire_format": "member2-normalized-1.0",
                "event": original
                | {"details": metadata["body"]["details"], "received_at": now().isoformat()},
            }
            headers = {"Authorization": "Bearer " + settings.sensors["linux-hooks-01"].token}
            duplicate = client.post("/internal/v1/member2/events", json=envelope, headers=headers)
            # Negative protocol mutation only. The genuine stored observation is
            # not edited or replaced by this untrusted contradictory claim.
            altered = copy.deepcopy(envelope)
            altered["event"]["details"]["coverage_scope"] = "negative-protocol-replay-test"
            conflicting_event = client.post(
                "/internal/v1/member2/events", json=altered, headers=headers
            )
            coverage = next(
                r["body"]
                for r in rows
                if r["kind"] == "coverage" and r["body"]["sensor_id"] == "linux-hooks-01"
            )
            duplicate_coverage = client.post(
                "/internal/v1/coverage", json=coverage, headers=headers
            )
            altered_coverage = copy.deepcopy(coverage)
            altered_coverage["lost_events"] += 1
            conflicting_coverage = client.post(
                "/internal/v1/coverage", json=altered_coverage, headers=headers
            )
            held = post(f"/api/v1/tasks/{task}/admit")
            assessment = client.get(f"/api/v1/tasks/{task}/result").json()
            terminated = post(f"/api/v1/tasks/{task}/terminate")
            snapshots["final"] = await_value(
                status, lambda s: s.get("finished") is True, seconds=30
            )
            # Transport fault injection: restore one genuinely captured,
            # acknowledged packet frame to pending, modelling a lost ACK. Never
            # mutate its payload or the application's immutable evidence ledger.
            queue_path = private / "observers" / capsule / "packet-queue" / "export.sqlite3"
            with sqlite3.connect(queue_path) as queue_db:
                saved = queue_db.execute(
                    "SELECT seq,payload FROM frames WHERE endpoint='events' AND delivered=1 LIMIT 1"
                ).fetchone()
                if saved is None:
                    raise RuntimeError("No genuine acknowledged packet available for restart test")
                queue_db.execute("UPDATE frames SET delivered=0 WHERE seq=?", (saved[0],))
            packet_identity = json.loads(saved[1])["event_id"]
            server.kill()
            server.wait(timeout=10)
            server = launch_server(private, image, port, continuous=True, model_digest=digest)

            def replay_delivered():
                with sqlite3.connect(queue_path) as queue_db:
                    return queue_db.execute(
                        "SELECT delivered,payload FROM frames WHERE seq=?", (saved[0],)
                    ).fetchone()

            recovered_frame = await_value(replay_delivered, lambda row: row[0] == 1, seconds=25)
            recovered_rows = evidence()
            restart_replay_ok = (
                recovered_frame[1] == saved[1]
                and sum(
                    r["kind"] == "event" and r["body"]["event"]["event_id"] == packet_identity
                    for r in recovered_rows
                )
                == 1
            )
            revision = post(f"/api/v1/tasks/{task}/revisions")
            second = post(f"/api/v1/tasks/{task}/launch")
            capsules.append(second["binding"]["capsule_id"])
            second_held = post(f"/api/v1/tasks/{task}/admit")
            second_stop = post(f"/api/v1/tasks/{task}/terminate")
            final_rows = evidence()
            checks = {
                "all_three_continuous_sources_observed": set(snapshots["initial"]["sources"])
                == {"process", "hooks", "packet"},
                "service_restart_replays_uncertain_ack_without_duplicate": restart_replay_ok,
                "genuine_process_file_connect_and_packet_events_delivered": {
                    "process_exec",
                    "file_access",
                    "connection_attempt",
                    "egress_flow",
                }
                <= event_types,
                "packet_collector_restarted_and_delivery_resumed": snapshots["after_restart"][
                    "restarts"
                ]["packet"]
                > 0,
                "partial_or_unknown_coverage_never_promoted": all(
                    r["body"]["status"] != "complete" for r in final_rows if r["kind"] == "coverage"
                ),
                "healthy_transport_does_not_admit_finance": before_conflict["agent_admitted"]
                is False,
                "identical_provenance_replay_acknowledged": duplicate.status_code == 200
                and duplicate.json()["duplicate"] is True,
                "contradictory_provenance_rejected": conflicting_event.status_code == 409,
                "identical_coverage_replay_acknowledged": duplicate_coverage.status_code == 200
                and duplicate_coverage.json()["duplicate"] is True,
                "contradictory_coverage_rejected": conflicting_coverage.status_code == 409,
                "conflict_holds_current_revision": "SOURCE_EVIDENCE_CONFLICT" in held["reasons"],
                "conflict_preserved_in_assessment": any(
                    f["reason_code"] == "CONFLICTING_DUPLICATE" for f in assessment["findings"]
                ),
                "cancellation_exit_and_revocation_verified": terminated["descendants_exited"]
                and terminated["channel_revoked"],
                "fresh_revision_not_poisoned_by_prior_conflict": revision["contract"][
                    "contract_version"
                ]
                == 2
                and "SOURCE_EVIDENCE_CONFLICT" not in second_held["reasons"],
                "fresh_revision_does_not_bypass_coverage": second_held["agent_admitted"] is False,
                "fresh_capsule_cleanup_verified": second_stop["descendants_exited"]
                and second_stop["channel_revoked"],
                "no_finance_admission_model_action_or_report": not any(
                    r["kind"] in {"admission", "broker", "report"} for r in final_rows
                ),
            }
        server.terminate()
        server.wait(timeout=45)
        store = Store(settings.database, settings.integrity_key)
        try:
            checks["evidence_integrity_verified"] = store.verify_chain()
        finally:
            store.db.close()
        result = {
            "observed_at": now().isoformat(),
            "mode": "real-linux-continuous-observer-lab",
            "image_id": image,
            "task_id": task,
            "capsule_ids": capsules,
            "checks": checks,
            "passed": all(checks.values()),
            "snapshots": snapshots,
            "admission_hold_reasons": before_conflict["reasons"],
            "event_classes": sorted(event_types),
            "negative_protocol_inputs": "Deliberately altered replay/coverage claims were rejected; they are not genuine telemetry",
            "protected_execution_ready": False,
            "agent_admitted": False,
            "full_report_recovery": "blocked: no complete source coverage from bootstrap birth",
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=45)
            except TimeoutError:
                server.kill()
                server.wait(timeout=10)
        for capsule in capsules:
            controller.terminate(capsule)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--approved-model-digest", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/linux/continuous_review.json")
    args = parser.parse_args()
    result = run(args.image_id, args.approved_model_digest, args.output)
    print(json.dumps({"passed": result["passed"], "checks": result["checks"]}, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
