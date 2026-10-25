"""Start the integrated local control plane on the actual trusted Linux host.

Credentials persist only in a root-private host directory and are never mounted
into capsules. Default protected execution remains fail-closed.
"""

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path

import uvicorn

from agentguard.capsules import StagedCapsules, private_directory
from application.api import create_app
from application.config import SensorIdentity, Settings
from application.staged_runtime import StagedRuntimeAdapter


def load_secrets(root: Path) -> dict:
    path = root / "credentials.json"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        values = {
            name: secrets.token_urlsafe(32)
            for name in ("owner", "runtime", "integrity", "process_sensor")
        }
        with os.fdopen(descriptor, "w") as stream:
            json.dump(values, stream)
            stream.flush()
            os.fsync(stream.fileno())
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise PermissionError("root-private credential file required")
        return json.load(stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/agentguard/control"))
    parser.add_argument("--lab-image-id")
    parser.add_argument(
        "--staged-image-id", help="Reviewed immutable Finance image ID; bootstrap staging only"
    )
    parser.add_argument("--host-id", default="linux-lab-01")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("this baseline requires the trusted rootful Linux host")
    os.umask(0o077)
    root = private_directory(args.state_dir)
    values = load_secrets(root)
    settings = Settings(
        owner_token=values["owner"],
        runtime_token=values["runtime"],
        integrity_key=values["integrity"],
        database=root / "evidence.sqlite3",
        approved_lab_image=args.lab_image_id,
        sensors={
            "linux-process-01": SensorIdentity(
                values["process_sensor"], args.host_id, ("host_sensor", "sensor_health")
            )
        },
    )
    print("AgentGuard integrated Linux dashboard: http://127.0.0.1:8000", flush=True)
    print("Owner token: " + settings.owner_token, flush=True)
    print(
        "Protected AI admission remains disabled until every required sensor scope is verified.",
        flush=True,
    )
    runtime = None
    if args.staged_image_id:
        runtime = StagedRuntimeAdapter(
            StagedCapsules(args.staged_image_id, state_root=root / "runtime"), args.host_id
        )
    uvicorn.run(create_app(settings, runtime), host="127.0.0.1", port=8000, access_log=False)


if __name__ == "__main__":
    main()
