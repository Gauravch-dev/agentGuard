"""Real loopback API, Finance bootstrap, cancellation and crash/restart experiment.

Uses the production staged adapter and conservative reviewer with no model. No
coverage is injected. A separately labelled docker-exec probe tests the broker
before admission; Finance Agent code is never admitted by this experiment.
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx
import uvicorn

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.platform import command
from agentguard.supervisor import ContinuousSupervisor
from application.api import create_app
from application.config import SensorIdentity, Settings
from application.models import now
from application.staged_runtime import StagedRuntimeAdapter
from application.store import Store
from scripts.start_linux import load_secrets, load_sensor_registry

ROOT = Path(__file__).resolve().parents[1]


def configuration(root, model_digest=None):
    values = load_secrets(root)
    return Settings(
        owner_token=values["owner"],
        runtime_token=values["runtime"],
        integrity_key=values["integrity"],
        database=root / "evidence.sqlite3",
        local_model_enabled=model_digest is not None,
        approved_model_digest=model_digest,
        sensors=load_sensor_registry(root / "sensors.json", "linux-lab-01")
        if (root / "sensors.json").exists()
        else {
            "linux-process-01": SensorIdentity(
                values["process_sensor"], "linux-lab-01", ("host_sensor", "sensor_health")
            )
        },
    )


def serve(root, image, port, *, continuous=False, model_digest=None):
    os.umask(0o077)
    settings = configuration(root, model_digest)
    runtime = StagedRuntimeAdapter(
        StagedCapsules(image, state_root=root / "runtime"), "linux-lab-01"
    )
    if continuous:
        runtime.supervisor = ContinuousSupervisor(
            runtime.controller,
            settings.sensors,
            "linux-lab-01",
            state_root=root / "observers",
            api_port=port,
        )
    uvicorn.run(
        create_app(settings, runtime),
        host="127.0.0.1",
        port=port,
        access_log=False,
        log_level="warning",
    )


def launch_server(root, image, port, *, continuous=False, model_digest=None):
    log = root / "server.log"
    with log.open("ab") as stream:
        process = subprocess.Popen(  # noqa: S603 - fixed local module, private state
            [
                sys.executable,
                "-m",
                "scripts.linux_lifecycle_lab",
                "--serve",
                "--state-dir",
                str(root),
                "--image-id",
                image,
                "--port",
                str(port),
            ]
            + (["--continuous-observers"] if continuous else [])
            + (["--approved-model-digest", model_digest] if model_digest else []),
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=stream,
        )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Private lab server failed; inspect private server log")
        try:
            with httpx.Client(trust_env=False, timeout=1) as client:
                if client.get(f"http://127.0.0.1:{port}/api/v1/health").status_code == 200:
                    return process
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    process.terminate()
    process.wait(timeout=15)
    raise RuntimeError("Private lab server did not become ready")


def run(image, output):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Trusted rootful Linux host required")
    os.umask(0o077)
    private = private_directory(Path("/var/lib/agentguard/lifecycle-lab") / uuid4().hex)
    settings = configuration(private)
    controller = StagedCapsules(image, state_root=private / "runtime")
    # Reserve an ephemeral loopback port; a collision fails safely during startup.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = None
    capsules = []
    records = []
    try:
        server = launch_server(private, image, port)
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

            checks = {}
            for scenario in ("cancel", "crash_restart"):
                task = post("/api/v1/tasks")["contract"]["task_id"]
                launched = post(f"/api/v1/tasks/{task}/launch")
                binding = launched["binding"]
                capsule = binding["capsule_id"]
                capsules.append(capsule)
                staged = controller.inspect(capsule)
                checks[scenario + "_real_bootstrap_staged"] = (
                    launched["state"] == "launch_requested"
                    and launched["agent_admitted"] is False
                    and staged["runtime_running"]
                    and not staged["admitted"]
                    and staged["image_id"] == image
                )
                # Trusted negative probe only, with the real capsule UID/cgroup.
                # The Finance workload is still blocked on its admission marker.
                probe = """
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(5)
s.connect('/run/agentguard/broker.sock')
try:
 s.sendall(b'{"schema_version":"1.0","request_id":"before-admission","operation":"data.get_department_totals","payload":{}}\\n')
 print(s.recv(32768).decode().strip())
except (ConnectionResetError,BrokenPipeError):
 print(json.dumps({'error':'request rejected'}))
finally: s.close()
"""
                denied = command(
                    [
                        "docker",
                        "exec",
                        "--user=65532:65532",
                        staged["container_id"],
                        "python",
                        "-I",
                        "-c",
                        probe,
                    ]
                )
                checks[scenario + "_real_peer_denied_before_admission"] = json.loads(denied) == {
                    "error": "request rejected"
                }
                held = post(f"/api/v1/tasks/{task}/admit")
                expected = {
                    "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE",
                    "LIVE_PLATFORM_ADMISSION_REVIEW_PENDING",
                    "LOCAL_MODEL_DISABLED",
                }
                checks[scenario + "_all_missing_gates_reported"] = held[
                    "agent_admitted"
                ] is False and expected <= set(held["reasons"])
                if scenario == "cancel":
                    stop = post(f"/api/v1/tasks/{task}/terminate")
                    checks["cancel_verified_response"] = (
                        stop["descendants_exited"] and stop["channel_revoked"]
                    )
                else:
                    # Only this script's exact child process is killed. Neither
                    # the dashboard nor any unrelated service is touched.
                    server.kill()
                    server.wait(timeout=10)
                    during = controller.inspect(capsule)
                    checks["crash_did_not_admit_agent"] = not during["admitted"]
                    server = launch_server(private, image, port)
                after = controller.inspect(capsule)
                task_after = client.get(f"/api/v1/tasks/{task}")
                task_after.raise_for_status()
                checks[scenario + "_verified_cleanup"] = (
                    after["state"] == "contained"
                    and not after["runtime_running"]
                    and after["descendants_exited"]
                    and after["channel_revoked"]
                    and not Path(after["channel_directory"], "broker.sock").exists()
                    and not Path(after["channel_directory"], "admitted").exists()
                    and task_after.json()["state"] == "interrupted"
                )
                records.append(
                    {
                        "scenario": scenario,
                        "task_id": task,
                        "binding": binding,
                        "container_id": after["container_id"],
                        "process_start_ticks": after["identity"]["start_ticks"],
                        "cgroup_inode": after["identity"]["cgroup_inode"],
                        "admission_hold_reasons": held["reasons"],
                        "contained_at": after["contained_at"],
                        "descendants_exited": after["descendants_exited"],
                        "channel_revoked": after["channel_revoked"],
                    }
                )
        server.send_signal(signal.SIGTERM)
        server.wait(timeout=20)
        server = None
        store = Store(settings.database, settings.integrity_key)
        try:
            checks["evidence_integrity_valid"] = store.verify_chain()
            checks["no_broker_model_or_report_action"] = all(
                not store.evidence(r["task_id"], kind)
                for r in records
                for kind in ("broker", "report", "admission")
            )
            checks["restart_revocation_persisted"] = any(
                r["body"]["reason"] == "APPLICATION_RESTART"
                for r in store.evidence(records[1]["task_id"], "channel_revocation")
            )
        finally:
            store.db.close()
        report = {
            "observed_at": now().isoformat(),
            "mode": "real-linux-application-lifecycle",
            "image_id": image,
            "checks": checks,
            "passed": all(checks.values()),
            "runs": records,
            "agent_admitted": False,
            "model_invoked": False,
            "protected_execution_ready": False,
            "scope": "Real HTTP API and Linux containers; no fixture controller, admission reviewer or coverage; docker-exec was a trusted negative peer probe only",
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)
        for capsule in capsules:
            controller.terminate(capsule)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "docs/linux/application_lifecycle.json"
    )
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--state-dir", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--continuous-observers", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--approved-model-digest", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve:
        serve(
            private_directory(args.state_dir),
            args.image_id,
            args.port,
            continuous=args.continuous_observers,
            model_digest=args.approved_model_digest,
        )
        return 0
    report = run(args.image_id, args.output)
    print(json.dumps({"passed": report["passed"], "checks": report["checks"]}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
