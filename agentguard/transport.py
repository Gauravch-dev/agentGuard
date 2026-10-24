"""Linux-only per-capsule Unix socket with host-observed peer authorization.

Not yet wired to protected Docker execution. Rootful, no userns baseline only.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import socketserver
import struct
import threading

from .brokers import BrokerDenied, BrokerSession
from .schema import ValidationError, canonical, strict_json


def process_identity(pid, proc_root=Path("/proc")):
    directory = Path(proc_root) / str(pid)
    # The command name can contain spaces or parentheses. Fields follow the LAST ')'.
    stat = (directory / "stat").read_text()
    fields = stat[stat.rfind(")") + 2:].split()
    start_ticks = fields[19]  # Linux proc stat field 22, after fields 1 and 2.
    cgroups = (directory / "cgroup").read_text().splitlines()
    unified = [line[3:] for line in cgroups if line.startswith("0::/")]
    if len(unified) != 1 or unified[0] == "/":
        raise PermissionError("unverified peer cgroup")
    return {"pid": pid, "start_ticks": start_ticks, "cgroup": unified[0]}


class PeerAuthorizer:
    def __init__(self, expected_cgroup, *, expected_uid=65532, proc_root=Path("/proc")):
        if not expected_cgroup.startswith("/") or expected_cgroup == "/":
            raise ValueError("trusted non-root cgroup required")
        self.cgroup, self.uid, self.proc_root = expected_cgroup, expected_uid, Path(proc_root)

    def authorize(self, connection):
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw)
        before = process_identity(pid, self.proc_root)
        if uid != self.uid or before["cgroup"] != self.cgroup:
            raise PermissionError("peer is outside the launcher-bound capsule")
        after = process_identity(pid, self.proc_root)
        if before != after:
            raise PermissionError("peer process changed during authorization")
        return before


class CapsuleSocket:
    MAX_REQUEST = 16_384

    def __init__(self, directory, session: BrokerSession, authorizer: PeerAuthorizer):
        self.directory = Path(directory)
        self.session, self.authorizer = session, authorizer
        self.server = self.thread = None

    def start(self):
        if not hasattr(socket, "SO_PEERCRED") or os.name != "posix":
            raise RuntimeError("Linux SO_PEERCRED required")
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        path = self.directory / "broker.sock"
        if len(os.fsencode(path)) >= 104:
            raise ValueError("Unix socket path too long")
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(2)
                try:
                    peer = owner.authorizer.authorize(self.connection)
                    raw = self.rfile.readline(owner.MAX_REQUEST + 1)
                    if len(raw) > owner.MAX_REQUEST or not raw.endswith(b"\n"):
                        raise ValidationError("invalid request framing")
                    # Revalidate peer after bounded read, not merely at connection time.
                    if owner.authorizer.authorize(self.connection) != peer:
                        raise PermissionError("peer changed")
                    result = owner.session.request(strict_json(raw))
                    response = {"ok": True, **result}
                except (PermissionError, OSError, ValidationError, BrokerDenied):
                    response = {"ok": False, "error": "request_denied"}
                except Exception:
                    response = {"ok": False, "error": "service_unavailable"}
                try:
                    self.wfile.write(canonical(response).encode() + b"\n")
                except OSError:
                    pass

        # Serial requests plus per-connection timeout bound worker count and lock contention.
        self.server = socketserver.UnixStreamServer(str(path), Handler)
        os.chmod(path, 0o600)
        os.chown(path, self.authorizer.uid, -1)
        os.chown(self.directory, self.authorizer.uid, -1)
        # The host parent stays inaccessible to that UID; only this directory is mounted.
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return path

    def close(self):
        self.session.revoke()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
        (self.directory / "broker.sock").unlink(missing_ok=True)
        if self.directory.exists():
            self.directory.rmdir()
