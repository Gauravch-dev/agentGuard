"""One-shot forwarding of an operator-owned Tetragon JSONL capture to the local API.

This does not install sensors, authenticate raw files, watch health, or claim coverage.
"""

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import TextIO

import httpx

from agentguard.schema import strict_json
from agentguard.sensors import Workload
from application.member2_bridge import normalize_tetragon


def forward_capture(stream: TextIO, workloads: list[Workload], sensor_id: str, token: str) -> dict:
    if len(token) < 32:
        raise ValueError("Distinct registered sensor credential required")
    forwarded, duplicates = 0, 0
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=10) as client:
        line_number = 0
        while True:
            line = stream.readline(65537)
            if not line:
                break
            line_number += 1
            if len(line.encode()) > 65536 or not line.endswith("\n"):
                raise ValueError(f"Invalid bounded JSONL frame at line {line_number}")
            reference = "tetragon:" + hashlib.sha256(line.encode()).hexdigest()
            shared, metadata = normalize_tetragon(
                strict_json(line), reference, sensor_id, workloads
            )
            value = shared.model_dump(mode="json") | {
                "received_at": metadata["collector_received_at"],
                "details": metadata["details"],
            }
            response = client.post(
                "http://127.0.0.1:8000/internal/v1/member2/events",
                headers={"Authorization": f"Bearer {token}"},
                json={"wire_format": "member2-normalized-1.0", "event": value},
            )
            response.raise_for_status()
            result = response.json()
            if result.get("accepted") is not True:
                raise ValueError(f"Collector event not accepted at line {line_number}")
            forwarded += 1
            duplicates += result.get("duplicate") is True
    return {
        "mode": "capture-forwarding",
        "forwarded": forwarded,
        "duplicates": duplicates,
        "sensor_health_verified": False,
        "coverage_promoted": False,
    }


def private_reader(path: Path) -> TextIO:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in {0, os.geteuid()}
            or info.st_mode & 0o022
        ):
            raise PermissionError(
                "Capture/lifecycle files must be operator-owned and not writable by other users"
            )
        return os.fdopen(descriptor, encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--workloads", type=Path, required=True)
    parser.add_argument("--sensor-id", required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Run the trusted capture forwarder on the Linux sensor host")
    try:
        with private_reader(args.workloads) as mapping:
            workloads = [Workload(**row) for row in strict_json(mapping.read(65537))]
        with private_reader(args.input) as stream:
            result = forward_capture(
                stream, workloads, args.sensor_id, os.environ.get("AG_SENSOR_TOKEN", "")
            )
        print(json.dumps(result))
        return 0
    except (ValueError, KeyError, TypeError, OSError, httpx.HTTPError) as exc:
        # Do not echo raw events, paths, tokens or HTTP response bodies.
        print(
            f"Capture forwarding failed: {type(exc).__name__}; no health/coverage assertion made",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
