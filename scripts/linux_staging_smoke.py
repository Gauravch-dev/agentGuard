"""Verify real bootstrap staging, admission hold and cleanup on the running app.

Uses only a new synthetic Finance task and the existing root-private owner token.
Does not admit agent code, alter coverage, or change the workload deadline.
"""

import argparse
import json
import time
from pathlib import Path

import httpx

from agentguard.schema import timestamp
from agentguard.source_time import nanoseconds
from scripts.start_linux import load_secrets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("var/staging-smoke.json"))
    args = parser.parse_args()
    control = Path("/var/lib/agentguard/control")
    owner = load_secrets(control)["owner"]
    checks, capsule, task = {}, None, None
    report = {
        "observed_at": timestamp(),
        "mode": "real-linux-staging-smoke",
        "checks": checks,
        "agent_admitted": False,
        "full_protected_mvp_complete": False,
    }
    with httpx.Client(
        base_url="http://127.0.0.1:8000",
        trust_env=False,
        headers={"Authorization": "Bearer " + owner},
        timeout=180,
    ) as client:

        def request(method, path, **kwargs):
            response = client.request(method, path, **kwargs)
            response.raise_for_status()
            return response.json()

        try:
            created = request("POST", "/api/v1/tasks", json={})
            task = created["contract"]["task_id"]
            base = f"/api/v1/tasks/{task}"
            report["task_id"] = task
            started = time.monotonic()
            launched = request("POST", base + "/launch", json={})
            report["staging_seconds"] = round(time.monotonic() - started, 3)
            binding = launched["binding"]
            capsule = binding["capsule_id"]
            checks["trusted_bootstrap_staged"] = launched["state"] == "launch_requested"
            checks["agent_not_admitted"] = launched["agent_admitted"] is False
            proof = json.loads((control / "observers" / capsule / "prebirth.json").read_text())
            checks["real_process_and_hook_witnesses"] = (
                proof["process_subscription_witnessed"]
                and proof["hook_subscription_witnessed"]
                and set(proof["witnesses"]) == {"process", "hooks"}
            )
            checks["witnesses_precede_bootstrap_birth"] = nanoseconds(
                proof["prepared_at"]
            ) < nanoseconds(binding["process_start"])
            runtime = json.loads((control / "runtime" / (capsule + ".json")).read_text())
            checks["original_execution_limit_retained"] = (
                nanoseconds(runtime["deadline"]) - nanoseconds(runtime["created_at"])
                <= created["contract"]["limits"]["max_execution_seconds"] * 10**9
            )
            held = request("POST", base + "/admit", json={})
            report["admission_reasons"] = held["reasons"]
            checks["incomplete_monitoring_still_holds_admission"] = (
                held["agent_admitted"] is False
                and held["state"] == "launch_requested"
                and "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE" in held["reasons"]
            )
            result = request("GET", base + "/result")
            checks["no_report_released"] = not result["reports"]
            checks["evidence_chain_verified"] = result["integrity_verified"]
        except Exception as exc:
            # Never serialize HTTP headers, credentials, private host paths or raw
            # source arguments into a report. Private diagnostics retain details.
            report["error_type"] = type(exc).__name__
        finally:
            if capsule is not None:
                try:
                    ended = request("POST", f"/api/v1/tasks/{task}/terminate", json={})
                    checks["cleanup_verified"] = ended["descendants_exited"] is True
                except Exception:
                    checks["cleanup_verified"] = False
    report["passed"] = len(checks) == 9 and all(checks.values()) and "error_type" not in report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
