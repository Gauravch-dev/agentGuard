"""Fixed broker socket lab workload; never represented as a model-driven agent."""

import argparse
import errno
import json
from pathlib import Path
import socket
import subprocess
import sys
from uuid import uuid4

parser = argparse.ArgumentParser()
parser.add_argument("--socket", required=True)
args = parser.parse_args()


def call(value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(8)
        connection.connect(args.socket)
        connection.sendall(json.dumps(value).encode() + b"\n")
        with connection.makefile("rb") as stream:
            raw = stream.readline(32769)
        if len(raw) > 32768:
            raise RuntimeError("oversize response")
        return json.loads(raw)


request = {
    "schema_version": "1.0",
    "request_id": uuid4().hex,
    "operation": "data.get_department_totals",
    "payload": {},
}
result = call(request)
allowed = result.get("receipt", {}).get("effect_status") == "completed"
foreign_context_rejected = "error" in result
request["task_id"] = "FORGED-TASK"
forged = call(request)
raw_output = call(
    {
        "schema_version": "1.0",
        "request_id": uuid4().hex,
        "operation": "output.save_department_summary",
        "payload": {"employees": [{"name": "Synthetic lab row", "salary": 123}], "currency": "INR"},
    }
)
raw_denied = (
    raw_output.get("receipt", {}).get("verdict") == "denied"
    and raw_output.get("receipt", {}).get("effect_status") == "blocked"
)
try:
    Path("/run/agentguard/forged-marker").write_text("must fail")
    mount_read_only = False
except OSError as exc:
    mount_read_only = exc.errno == errno.EROFS
child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
child_started = child.poll() is None
print(
    json.dumps(
        {
            "evidence_source": "fixed in-container socket lab, not independent OS telemetry",
            "aggregate_allowed": allowed,
            "foreign_context_rejected": foreign_context_rejected,
            "forged_task_rejected": "error" in forged,
            "raw_row_output_denied": raw_denied,
            "lab_child_started": child_started,
            "channel_mount_read_only": mount_read_only,
        }
    ),
    flush=True,
)
