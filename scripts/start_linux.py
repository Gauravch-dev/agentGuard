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
from agentguard.schema import strict_json
from agentguard.supervisor import ContinuousSupervisor
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


def load_sensor_registry(path: Path, host_id: str) -> dict[str, SensorIdentity]:
    """Load trusted source credentials; registration never certifies readiness."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o077
            or info.st_size > 16384
        ):
            raise PermissionError("Root-private sensor registry required")
        registry = strict_json(stream.read())
    if not isinstance(registry, dict) or not registry or len(registry) > 16:
        raise ValueError("Bounded sensor registry required")
    result = {}
    for sensor_id, record in registry.items():
        if not isinstance(record, dict) or set(record) != {"token", "host_id", "sources"}:
            raise ValueError("Invalid source registration")
        if (
            record["host_id"] != host_id
            or not set(record["sources"]) <= {"host_sensor", "network_sensor", "sensor_health"}
            or not record["sources"]
        ):
            raise ValueError("Sensor scope cannot impersonate another host, broker or runtime")
        result[sensor_id] = SensorIdentity(record["token"], host_id, tuple(record["sources"]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/agentguard/control"))
    parser.add_argument("--lab-image-id")
    parser.add_argument(
        "--staged-image-id", help="Reviewed immutable Finance image ID; bootstrap staging only"
    )
    parser.add_argument("--host-id", default="linux-lab-01")
    parser.add_argument(
        "--sensor-registry",
        type=Path,
        help="Root-private explicit source registry; no coverage/readiness implied",
    )
    parser.add_argument(
        "--approved-model-digest",
        help="Reviewed SHA-256 of local qwen2.5:7b; enables only trusted loopback model broker",
    )
    parser.add_argument(
        "--continuous-observers",
        action="store_true",
        help="Start genuine continuous host observers for staged tasks; known coverage gaps still hold admission",
    )
    args = parser.parse_args()
    if args.continuous_observers and (not args.staged_image_id or not args.sensor_registry):
        parser.error("--continuous-observers requires --staged-image-id and --sensor-registry")
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
        local_model_enabled=args.approved_model_digest is not None,
        approved_model_digest=args.approved_model_digest,
        sensors=load_sensor_registry(args.sensor_registry, args.host_id)
        if args.sensor_registry
        else {
            "linux-process-01": SensorIdentity(
                values["process_sensor"], args.host_id, ("host_sensor", "sensor_health")
            )
        },
    )
    print("AgentGuard integrated Linux dashboard: http://127.0.0.1:8000", flush=True)
    print("Owner credential is stored in the root-private control state.", flush=True)
    print(
        "Protected AI admission remains disabled until every required sensor scope is verified.",
        flush=True,
    )
    runtime = None
    if args.staged_image_id:
        controller = StagedCapsules(args.staged_image_id, state_root=root / "runtime")
        runtime = StagedRuntimeAdapter(controller, args.host_id)
        if args.continuous_observers:
            runtime.supervisor = ContinuousSupervisor(
                controller, settings.sensors, args.host_id, state_root=root / "observers"
            )
    uvicorn.run(create_app(settings, runtime), host="127.0.0.1", port=8000, access_log=False)


if __name__ == "__main__":
    main()
