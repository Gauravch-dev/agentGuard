"""Real independent namespace packet tap, self-check and refused external attempt."""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.network_tap import capture
from agentguard.platform import command
from application.authority import Authority
from application.models import now
from application.store import Store

ROOT = Path(__file__).resolve().parents[1]


def run(image, output):
    os.umask(0o077)
    private = private_directory(Path("/var/lib/agentguard/network-lab") / uuid4().hex)
    store = Store(private / "evidence.sqlite3", os.urandom(32).hex())
    contract = Authority(store).create("linux-lab-owner", "NETWORK-" + uuid4().hex)
    controller = StagedCapsules(image, state_root=private / "runtime")
    value = controller.prepare(contract.model_dump(mode="json"))
    sensor = None
    try:
        ready = private / "tap.ready"
        with (
            (private / "tap.json").open("xb") as stream,
            (private / "tap.stderr").open("xb") as errors,
        ):
            sensor = subprocess.Popen(  # noqa: S603 - fixed trusted helper, private runtime record
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
                stdout=stream,
                stderr=errors,
            )
            deadline = time.monotonic() + 10
            while not ready.exists():
                if sensor.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Independent packet tap failed; inspect private stderr")
                time.sleep(0.05)
            probe = """
import json,socket
r={}
for name,target in [('loopback_selfcheck',('127.0.0.1',49191)),('external_attempt',('192.0.2.53',53))]:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.5)
 try: r[name]={'bytes_sent':s.sendto(b'agentguard-synthetic',target)}
 except OSError as e: r[name]={'errno':e.errno}
 finally: s.close()
print(json.dumps(r))
"""
            attempts = json.loads(
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
            sensor.wait(timeout=15)
        if sensor.returncode:
            raise RuntimeError("Independent packet capture failed")
        result = json.loads((private / "tap.json").read_text())
        outgoing = [p for p in result["packets"] if p["packet_type"] == 4]
        checks = {
            "real_loopback_packet_observed": any(
                p.get("destination_scope") == "loopback" for p in outgoing
            ),
            "external_attempt_returned_error": "errno" in attempts["external_attempt"],
            "no_nonloopback_outgoing_frame_observed": not any(
                p.get("destination_scope") == "non_loopback" for p in outgoing
            ),
            "kernel_packet_drops_zero_in_bounded_window": result["kernel_drops"] == 0,
            "no_parser_or_capacity_gap": result["parser_or_capacity_gaps"] == 0,
            "payload_not_retained": not result["payload_retained"],
            "finance_agent_not_admitted": not controller.inspect(value["capsule_id"])["admitted"],
        }
        report = {
            "observed_at": now().isoformat(),
            "mode": "real-linux-independent-packet-lab",
            "image_id": image,
            "container_id": value["container_id"],
            "capture": result,
            "attempt_results": attempts,
            "checks": checks,
            "passed": all(checks.values()),
            "protected_execution_ready": False,
            "limitations": [
                "Bounded packet window, not continuous production coverage",
                "A failed external connect/send may produce no packet; attempt evidence needs syscall sensor",
                "Namespace attribution only; no sender PID or packet content claim",
            ],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        if sensor is not None and sensor.poll() is None:
            sensor.terminate()
            sensor.wait(timeout=10)
        controller.terminate(value["capsule_id"])
        store.db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id")
    parser.add_argument("--capture-record", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--ready", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/linux/network_lab.json")
    args = parser.parse_args()
    if args.capture_record:
        print(json.dumps(capture(args.capture_record, 4, args.ready)))
        return 0
    result = run(args.image_id, args.output)
    print(json.dumps({"passed": result["passed"], "checks": result["checks"]}, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
