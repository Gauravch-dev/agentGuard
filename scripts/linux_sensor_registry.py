"""Create separate private source credentials. This does not start or certify sensors."""

import argparse
import json
import os
import secrets
from pathlib import Path

from agentguard.capsules import private_directory
from scripts.start_linux import load_secrets, load_sensor_registry


def create(root: Path, host_id: str) -> Path:
    root = private_directory(root)
    secrets_by_role = load_secrets(root)
    path = root / "sensors.json"
    records = {
        "linux-process-01": {
            "token": secrets_by_role["process_sensor"],
            "host_id": host_id,
            "sources": ["host_sensor", "sensor_health"],
        },
        "linux-hooks-01": {
            "token": secrets.token_urlsafe(32),
            "host_id": host_id,
            "sources": ["host_sensor", "sensor_health"],
        },
        "linux-packet-01": {
            "token": secrets.token_urlsafe(32),
            "host_id": host_id,
            "sources": ["network_sensor", "sensor_health"],
        },
    }
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        load_sensor_registry(path, host_id)
        return path
    with os.fdopen(descriptor, "w") as stream:
        json.dump(records, stream)
        stream.flush()
        os.fsync(stream.fileno())
    load_sensor_registry(path, host_id)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/agentguard/control"))
    parser.add_argument("--host-id", default="linux-lab-01")
    args = parser.parse_args()
    create(args.state_dir, args.host_id)
    print("Private process/hook/packet credentials prepared; no readiness or coverage assertion.")


if __name__ == "__main__":
    main()
