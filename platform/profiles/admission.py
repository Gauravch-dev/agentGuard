"""Trusted image bootstrap. No agent code runs before the host's admission file."""

import os
from pathlib import Path
import stat
import sys
import time

gate = Path("/run/agentguard/admitted")
deadline = time.monotonic() + 180
while time.monotonic() < deadline:
    try:
        descriptor = os.open(gate, os.O_RDONLY | os.O_NOFOLLOW)
    except (FileNotFoundError, PermissionError):
        time.sleep(0.05)
        continue
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222:
            raise RuntimeError("invalid host admission file")
        if os.read(descriptor, 32) != b"admitted-v1\n":
            raise RuntimeError("invalid admission marker")
    finally:
        os.close(descriptor)
    os.execv(
        sys.executable,
        [
            sys.executable,
            "-I",
            "/opt/agentguard/workload.py",
            "--socket",
            "/run/agentguard/broker.sock",
        ],
    )
raise SystemExit("host admission deadline expired")
