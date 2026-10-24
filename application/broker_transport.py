"""Linux UDS transport: actual peer checks before/after reading; bounded strict JSON."""

import asyncio
import os
import socket
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from agentguard.schema import strict_json
from application.brokers import Broker, ChannelContext
from application.models import BrokerRequest

PeerResolver = Callable[[int, int, int], ChannelContext]


class ChannelAuthorizer(Protocol):
    def authorize(self, connection: Any) -> ChannelContext: ...


async def serve_socket(
    path: Path,
    broker: Broker,
    resolve_peer: PeerResolver | None = None,
    *,
    authorizer: ChannelAuthorizer | None = None,
    capsule_uid: int | None = None,
) -> asyncio.AbstractServer:
    if not hasattr(socket, "SO_PEERCRED") or os.name != "posix":
        raise RuntimeError("Verified Unix peer credentials require Linux")
    if (resolve_peer is None) == (authorizer is None):
        raise ValueError("Provide exactly one trusted peer verifier")
    if path.exists() or path.parent.stat().st_mode & 0o077:
        raise PermissionError("Use a fresh socket in a private trusted directory")
    if capsule_uid is not None:
        if capsule_uid != 65532 or os.geteuid() != 0:
            raise PermissionError("Only reviewed rootful UID 65532 mapping is supported")
        parent = path.parent.parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise PermissionError("Per-capsule socket requires a private host-owned parent")

    def verify(raw_socket: Any) -> ChannelContext:
        if authorizer is not None:
            return authorizer.authorize(raw_socket)
        pid, uid, gid = struct.unpack(
            "3i", raw_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        assert resolve_peer is not None
        return resolve_peer(pid, uid, gid)

    async def connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw_socket = writer.get_extra_info("socket")
            channel = verify(raw_socket)
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            if len(raw) > 16384 or not raw.endswith(b"\n"):
                raise ValueError("Invalid frame")
            if verify(raw_socket) != channel:
                raise PermissionError("Peer changed while reading")
            request = BrokerRequest.model_validate(strict_json(raw))
            response = await asyncio.to_thread(broker.handle, channel, request)
            encoded = response.model_dump_json().encode() + b"\n"
            if len(encoded) > 32768:
                raise ValueError("Response exceeds limit")
            writer.write(encoded)
            await writer.drain()
        except (PermissionError, ValueError, OSError, TimeoutError):
            writer.write(b'{"error":"request rejected"}\n')
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    previous = os.umask(0o077)
    server = None
    try:
        server = await asyncio.start_unix_server(connection, path=path, limit=16385)
        path.chmod(0o600)
        if capsule_uid is not None:
            os.chown(path, capsule_uid, -1)
            os.chown(path.parent, capsule_uid, -1)
        return server
    except BaseException:
        if server is not None:
            server.close()
            await server.wait_closed()
        path.unlink(missing_ok=True)
        raise
    finally:
        os.umask(previous)
