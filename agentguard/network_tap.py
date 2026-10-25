"""Independent AF_PACKET observation inside one verified capsule network namespace.

Run only in a dedicated trusted sensor process. The host's mount/PID/cgroup
namespaces are retained. Payload contents are never persisted or exported.
"""

import ipaddress
import os
import socket
import struct
import time
from pathlib import Path

from agentguard.capsules import RuntimeRecord
from agentguard.transport import process_identity


def packet_metadata(frame, address):
    if len(frame) < 14:
        raise ValueError("Truncated Ethernet frame")
    protocol = int.from_bytes(frame[12:14], "big")
    data = frame[14:]
    if protocol == 0x0800 and len(data) >= 20:
        length = (data[0] & 15) * 4
        if data[0] >> 4 != 4 or length < 20 or len(data) < length:
            raise ValueError("Invalid IPv4 header")
        source, destination = (
            str(ipaddress.ip_address(data[12:16])),
            str(ipaddress.ip_address(data[16:20])),
        )
        transport = data[9]
    elif protocol == 0x86DD and len(data) >= 40:
        if data[0] >> 4 != 6:
            raise ValueError("Invalid IPv6 header")
        length = 40
        source, destination = (
            str(ipaddress.ip_address(data[8:24])),
            str(ipaddress.ip_address(data[24:40])),
        )
        transport = data[6]
    else:
        return {"ether_type": protocol, "frame_bytes": len(frame), "packet_type": address[2]}
    return {
        "source_ip": source,
        "destination_ip": destination,
        "ip_protocol": transport,
        "frame_bytes": len(frame),
        "packet_type": address[2],
        "interface": address[0],
        "destination_scope": "loopback"
        if ipaddress.ip_address(destination).is_loopback
        else "non_loopback",
    }


def capture(record_path: Path, seconds: int, ready: Path):
    if not 1 <= seconds <= 30:
        raise ValueError("Bounded capture of 1 to 30 seconds required")
    value = RuntimeRecord(record_path).read()
    identity = value["identity"]
    pid = identity["pid"]
    if process_identity(pid) != {key: identity[key] for key in ("pid", "start_ticks", "cgroup")}:
        raise PermissionError("Capsule process identity changed before namespace capture")
    namespace = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        inode = os.fstat(namespace).st_ino
        if inode == Path("/proc/self/ns/net").stat().st_ino:
            raise PermissionError("Host network namespace cannot be monitored by capsule tap")
        if process_identity(pid) != {
            key: identity[key] for key in ("pid", "start_ticks", "cgroup")
        }:
            raise PermissionError("Capsule changed while opening network namespace")
        os.setns(namespace, 0)
    finally:
        os.close(namespace)
    if Path("/proc/self/ns/net").stat().st_ino != inode:
        raise PermissionError("Failed to enter captured capsule namespace")
    start = time.monotonic()
    packets, parser_gaps = [], 0
    # ETH_P_ALL, all interfaces in THIS namespace only. Linux's packet_type
    # distinguishes outgoing frames; a connect syscall is never called a flow.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as stream:
        stream.settimeout(0.1)
        ready.write_text("af-packet-ready\n")
        while time.monotonic() < start + seconds:
            try:
                frame, address = stream.recvfrom(65536)
            except TimeoutError:
                continue
            try:
                metadata = packet_metadata(frame, address)
                if len(packets) < 1024:
                    packets.append(metadata)
                else:
                    parser_gaps += 1
            except ValueError:
                parser_gaps += 1
        received, dropped = struct.unpack("=II", stream.getsockopt(263, 6, 8))
    return {
        "network_namespace_inode": inode,
        "capsule_id": value["capsule_id"],
        "cgroup_inode": identity["cgroup_inode"],
        "packets": packets,
        "kernel_packet_count": received,
        "kernel_drops": dropped,
        "parser_or_capacity_gaps": parser_gaps,
        "capture_seconds": time.monotonic() - start,
        "payload_retained": False,
        "coverage_status": "partial",
        "scope": "Actual AF_PACKET namespace observations; no individual sender PID or encrypted contents inferred",
    }
