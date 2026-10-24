# ruff: noqa: E402
"""Real two-container peer denial, admission, revocation and watchdog experiment.

Uses the integrated application's actual authority and broker with a disabled model.
It does not relax output coverage and is never an AI/model acceptance result.
"""

import argparse
import asyncio
import json
import secrets
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.platform import command
from application.authority import Authority
from application.broker_transport import serve_socket
from application.brokers import Broker, ChannelContext
from application.member2_bridge import Member2ChannelAuthorizer
from application.model_provider import DisabledModel
from application.models import Binding, Receipt, now
from application.store import Store
from application.tere import reconcile


async def stopped(controller, capsule_id, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = await asyncio.to_thread(controller.inspect, capsule_id)
        if (
            result["state"] == "contained"
            and result["descendants_exited"]
            and result["channel_revoked"]
        ):
            return result
        await asyncio.sleep(0.05)
    raise RuntimeError("capsule exit/channel revocation not confirmed")


def public_identity(value):
    return {
        "capsule_id": value["capsule_id"],
        "container_id": value["container_id"],
        "cgroup_inode": value["identity"]["cgroup_inode"],
        "process_start_ticks": value["identity"]["start_ticks"],
        "state": value["state"],
        "descendants_exited": value["descendants_exited"],
        "channel_revoked": value["channel_revoked"],
    }


async def run(image_id, output):
    private = private_directory(Path("/var/lib/agentguard/socket-lab") / uuid4().hex)
    store = Store(private / "evidence.sqlite3", secrets.token_urlsafe(32))
    authority = Authority(store)
    broker = Broker(store, authority, DisabledModel())
    bindings = {}

    def can_admit(value):
        b = bindings.get(value["capsule_id"])
        return b is not None and broker.resolve(ChannelContext(b.channel_id, b.capsule_id)) == b

    controller = StagedCapsules(image_id, state_root=private / "runtime", admission_check=can_admit)
    servers, created = [], []
    try:
        values = []
        for name in ("SOCKET-ALLOW", "SOCKET-FOREIGN"):
            contract = authority.create("linux-lab-owner", name)
            authority.transition(name, "launch_requested")
            value = await asyncio.to_thread(controller.prepare, contract.model_dump(mode="json"))
            created.append(value["capsule_id"])
            identity = value["identity"]
            binding = Binding(
                task_id=name,
                contract_version=1,
                capsule_id=value["capsule_id"],
                host_id="linux-lab-01",
                cgroup_id="cg-" + str(identity["cgroup_inode"]),
                process_start=datetime.fromisoformat(identity["process_start_observed_at"]),
                registered_at=now(),
                channel_id=uuid4().hex,
            )
            store.append("binding", binding.capsule_id, name, binding.model_dump(mode="json"))
            authority.transition(name, "running")
            bindings[binding.capsule_id] = binding
            values.append(value)
        allowed, foreign = values
        recovered = controller.recover()
        binding = bindings[allowed["capsule_id"]]
        identity = allowed["identity"]
        authorizer = Member2ChannelAuthorizer(
            broker,
            binding,
            identity["cgroup"],
            int(identity["start_ticks"]),
            identity["cgroup_inode"],
        )
        # Deliberate trusted negative-test wiring: the second capsule can see a
        # socket whose authorizer expects the FIRST capsule. Equal UID/path access
        # must not authorize a different cgroup. No protected data/model is exposed.
        for value in values:
            servers.append(
                await serve_socket(
                    Path(value["channel_directory"]) / "broker.sock",
                    broker,
                    authorizer=authorizer,
                    capsule_uid=65532,
                )
            )
        before = await asyncio.to_thread(controller.inspect, allowed["capsule_id"])
        admission_held = not before["admitted"] and not store.evidence("SOCKET-ALLOW", "broker")
        await asyncio.to_thread(controller.admit, foreign["capsule_id"])
        foreign_done = await stopped(controller, foreign["capsule_id"])
        foreign_result = json.loads(command(["docker", "logs", foreign["container_id"]]))
        foreign_denied = foreign_result["foreign_context_rejected"] and not store.evidence(
            "SOCKET-FOREIGN", "broker"
        )
        await asyncio.to_thread(controller.admit, allowed["capsule_id"])
        allowed_done = await stopped(controller, allowed["capsule_id"])
        allowed_result = json.loads(command(["docker", "logs", allowed["container_id"]]))
        receipts = [
            Receipt.model_validate(row["body"]["response"]["receipt"])
            for row in store.evidence("SOCKET-ALLOW", "broker")
        ]
        findings = reconcile(
            authority.get("SOCKET-ALLOW"),
            binding,
            receipts,
            [],
            [],
            datetime.fromisoformat(authority.record("SOCKET-ALLOW")["started_at"]),
            now(),
            store.verify_chain(),
        )
        authority.transition("SOCKET-ALLOW", "interrupted")
        try:
            broker.resolve(ChannelContext(binding.channel_id, binding.capsule_id))
            revoked = False
        except (PermissionError, ValueError):
            revoked = True
        # A separate launcher request process exits immediately after prepare.
        # Its detached watchdog must still enforce the short, locally approved
        # lab contract's deadline without admission or an application server.
        code = """
import json,sys,os
from pathlib import Path
from agentguard.authority import Authority,sample_contract
from agentguard.store import Store
from agentguard.capsules import StagedCapsules
root=Path(sys.argv[2])
proposal=sample_contract('WATCHDOG-LAB')
proposal['limits']['max_execution_seconds']=4
contract=Authority(Store(root/'authority')).approve(proposal)
value=StagedCapsules(sys.argv[1],state_root=root/'runtime').prepare(contract)
print(value['capsule_id'],flush=True)
os._exit(23)
"""
        request = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-c", code, image_id, str(private)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        watchdog_id = request.stdout.strip()
        created.append(watchdog_id)
        watchdog_done = await stopped(controller, watchdog_id, timeout=10)
        checks = {
            "no_broker_action_before_admission": admission_held,
            "service_recovery_preserves_staged_capsules": set(recovered) == set(created[:2]),
            "bound_capsule_aggregate_allowed": allowed_result["aggregate_allowed"],
            "forged_task_field_rejected": allowed_result["forged_task_rejected"],
            "raw_row_output_denied_by_actual_broker": allowed_result["raw_row_output_denied"],
            "blocked_attempt_and_missing_coverage_both_preserved": {"Blocked", "Unverified"}
            <= {finding.classification for finding in findings},
            "read_only_channel_mount": allowed_result["channel_mount_read_only"],
            "live_child_started_before_parent_exit": allowed_result["lab_child_started"],
            "same_uid_foreign_cgroup_rejected": foreign_denied,
            "channel_revoked_after_lifecycle_change": revoked,
            "request_process_failed_before_watchdog_containment": request.returncode == 23
            and watchdog_done["descendants_exited"],
            "all_descendants_exited": all(
                v["descendants_exited"] for v in (allowed_done, foreign_done, watchdog_done)
            ),
            "all_channels_revoked": all(
                v["channel_revoked"] for v in (allowed_done, foreign_done, watchdog_done)
            ),
            "no_output_coverage_bypass": not store.evidence("SOCKET-ALLOW", "report"),
            "evidence_integrity_valid": store.verify_chain(),
        }
        result = {
            "observed_at": now().isoformat(),
            "mode": "real-linux-socket-lab",
            "image_id": image_id,
            "passed": all(checks.values()),
            "checks": checks,
            "allowed_capsule": public_identity(allowed_done),
            "foreign_capsule": public_identity(foreign_done),
            "watchdog_capsule": public_identity(watchdog_done),
            "protected_execution_ready": False,
            "model_invoked": False,
            "broker_receipts": [receipt.model_dump(mode="json") for receipt in receipts],
            "security_findings": [finding.model_dump(mode="json") for finding in findings],
            "scope": "actual Linux peer/cgroup, read-only channel, admission and deadline experiment; not full sensor coverage or AI acceptance",
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        for capsule_id in created:
            await asyncio.to_thread(controller.terminate, capsule_id)
        for server in servers:
            server.close()
            await server.wait_closed()
        store.db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/linux/socket_lab.json")
    args = parser.parse_args()
    result = asyncio.run(run(args.image_id, args.output))
    print(
        json.dumps(
            {
                "passed": result["passed"],
                "checks": result["checks"],
                "protected_execution_ready": False,
            },
            indent=2,
        )
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
