"""Real peer credential tests run on Linux; never claim Windows tested SO_PEERCRED."""

import os
import socket
import tempfile
import unittest

from agentguard.transport import PeerAuthorizer, process_identity


@unittest.skipUnless(hasattr(socket, "SO_PEERCRED") and os.path.exists("/proc/self/cgroup"), "Linux peer credential/cgroup test requires Linux")
class LinuxPeerTests(unittest.TestCase):
    def test_real_socket_rejects_unbound_cgroup(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaises(PermissionError):
                PeerAuthorizer("/agentguard/nonexistent", expected_uid=os.getuid()).authorize(left)
        finally:
            left.close()
            right.close()
