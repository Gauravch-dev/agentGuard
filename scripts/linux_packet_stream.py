"""Continuous trusted AF_PACKET helper, one verified capsule namespace only.

Emits metadata and actual counter heartbeats, never payloads or fabricated PIDs.
Its lifetime is bounded by the runtime record and its original host parent.
"""

import argparse
import json
import os
import socket
import struct
import time
from pathlib import Path

from agentguard.capsules import RuntimeRecord, deadline_reached
from agentguard.network_tap import packet_metadata
from agentguard.schema import timestamp
from agentguard.transport import process_identity


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def run(path: Path):
    record = RuntimeRecord(path)
    value = record.read()
    identity = value["identity"]
    expected = {key: identity[key] for key in ("pid", "start_ticks", "cgroup")}
    parent = os.getppid()
    parent_stat = Path(f"/proc/{parent}/stat").read_text()
    cgroup = Path("/sys/fs/cgroup") / identity["cgroup"].lstrip("/")
    if (
        cgroup.stat().st_ino != identity["cgroup_inode"]
        or process_identity(identity["pid"]) != expected
    ):
        raise PermissionError("Capsule identity changed")
    descriptor = os.open(f"/proc/{identity['pid']}/ns/net", os.O_RDONLY)
    try:
        inode = os.fstat(descriptor).st_ino
        if inode == Path("/proc/self/ns/net").stat().st_ino:
            raise PermissionError("Host namespace refused")
        if process_identity(identity["pid"]) != expected:
            raise PermissionError("Process changed while opening namespace")
        os.setns(descriptor, 0)
    finally:
        os.close(descriptor)
    if Path("/proc/self/ns/net").stat().st_ino != inode:
        raise PermissionError("Namespace entry failed")
    birth = timestamp()
    monotonic_start = time.monotonic()
    window_start = birth
    packets, dropped, gaps = 0, 0, 0
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as stream:
        stream.settimeout(0.1)
        emit({"kind": "ready", "observed_at": birth, "network_namespace_inode": inode})
        next_tick = time.monotonic() + 1
        while time.monotonic() - monotonic_start <= 180:
            try:
                frame, address = stream.recvfrom(65536)
                metadata = packet_metadata(frame, address)
                # Loopback frames are retained as their actual interface scope;
                # they must never be described as an external transfer.
                emit(
                    {
                        "kind": "packet",
                        "observed_at": timestamp(),
                        "metadata": metadata,
                        "network_namespace_inode": inode,
                        "capsule_id": value["capsule_id"],
                    }
                )
            except TimeoutError:
                pass
            except ValueError:
                gaps += 1
            if time.monotonic() < next_tick:
                continue
            received, lost = struct.unpack("=II", stream.getsockopt(263, 6, 8))
            packets += received
            dropped += lost
            end = timestamp()
            emit(
                {
                    "kind": "health",
                    "start": window_start,
                    "end": end,
                    "network_namespace_inode": inode,
                    "packets": packets,
                    "dropped": dropped,
                    "parser_gaps": gaps,
                }
            )
            window_start, next_tick = end, time.monotonic() + 1
            current_parent = Path(f"/proc/{parent}/stat").read_text()
            # Compare field 22 rather than mutable command state/CPU counters.
            if (
                os.getppid() != parent
                or current_parent[current_parent.rfind(")") + 2 :].split()[19]
                != parent_stat[parent_stat.rfind(")") + 2 :].split()[19]
            ):
                break
            current = record.read()
            if current["state"] == "contained" or deadline_reached(current):
                break
        emit({"kind": "stopped", "observed_at": timestamp(), "network_namespace_inode": inode})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    run(args.record)


if __name__ == "__main__":
    main()
