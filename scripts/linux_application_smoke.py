"""Authenticated real API-to-Docker fixed lab and protected-readiness refusal.

The owner credential is read from private host state, never a command argument.
No agent/model request or output-coverage bypass is performed.
"""

import json
from pathlib import Path

import httpx

from agentguard.platform import command
from application.models import now
from scripts.start_linux import load_secrets


def main():
    root = Path(__file__).resolve().parents[1]
    private = Path("/var/lib/agentguard/control")
    if not (private / "credentials.json").is_file():
        raise RuntimeError("start the trusted Linux application first")
    owner = load_secrets(private)["owner"]
    with httpx.Client(
        base_url="http://127.0.0.1:8000",
        trust_env=False,
        follow_redirects=False,
        timeout=40,
        headers={"Authorization": "Bearer " + owner},
    ) as client:
        health = client.get("/api/v1/health")
        health.raise_for_status()
        created = client.post("/api/v1/tasks", json={})
        created.raise_for_status()
        task_id = created.json()["contract"]["task_id"]
        lab = client.post(f"/api/v1/tasks/{task_id}/isolation-lab", json={})
        lab.raise_for_status()
        after_lab = client.get(f"/api/v1/tasks/{task_id}").json()
        live_before = command(["docker", "ps", "-q", "--filter", "label=agentguard.mode=staged"])
        launch = client.post(f"/api/v1/tasks/{task_id}/launch", json={})
        after_launch = client.get(f"/api/v1/tasks/{task_id}")
        after_launch.raise_for_status()
        live_after = command(["docker", "ps", "-q", "--filter", "label=agentguard.mode=staged"])
        data = lab.json()["result"]
        checks = {
            "health_ready": health.json()["application"] == "ready",
            "real_api_lab_passed": data["probes"]["passed"],
            "real_api_lab_termination_confirmed": data["termination"]["confirmed"],
            "fixed_lab_did_not_mark_business_complete": after_lab["state"] == "approved",
            "protected_launch_refused": launch.status_code == 503,
            "no_protected_binding_created": after_launch.json()["binding"] is None,
            "no_new_staged_container_from_refused_launch": live_before == live_after,
            "no_live_isolation_claim": health.json()["live_isolation_verified"] is False,
        }
        report = {
            "observed_at": now().isoformat(),
            "mode": "real-linux-application-smoke",
            "task_id": task_id,
            "checks": checks,
            "passed": all(checks.values()),
            "task_state_after_refusal": after_launch.json()["state"],
            "fixed_lab_capsule_id": data["capsule_id"],
            "protected_execution_ready": False,
            "model_invoked": False,
        }
    (root / "docs/linux/application_smoke.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
