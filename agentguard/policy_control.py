"""Serialize this project's host-sensor policy mutations across control planes.

No arbitrary policy names, replacement, command options or sensor targets are
accepted. A failed/timed-out load stays a failed load; callers retain their gates.
"""

import math
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from agentguard.capsules import private_directory
from agentguard.platform import command
from agentguard.schema import strict_json


@contextmanager
def policy_lock(root=Path("/run/agentguard/policy-control"), *, seconds=35):
    import fcntl

    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, (int, float))
        or not math.isfinite(seconds)
        or not 0 < seconds <= 35
    ):
        raise ValueError("Bounded policy lease duration required")
    directory = private_directory(root)
    descriptor = os.open(directory / "mutation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise PermissionError("Private host policy lease required")
        deadline = time.monotonic() + seconds
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Host policy mutation lease unavailable") from None
                time.sleep(0.05)
        yield
    finally:
        os.close(descriptor)


def install_policy(path, name):
    if not re.fullmatch(r"agentguard-[a-f0-9]{32}", name):
        raise ValueError("Exact managed policy identity required")
    private_directory(Path(path).parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o077
            or info.st_size > 65536
        ):
            raise PermissionError("Private bounded host policy required")
        policy = strict_json(stream.read())
    if policy.get("metadata", {}).get("name") != name:
        raise ValueError("Policy identity mismatch")
    remote = "/etc/tetragon/" + name + ".json"
    with policy_lock():
        command(["docker", "cp", str(path), "agentguard-tetragon:" + remote])
        command(
            [
                "docker",
                "exec",
                "agentguard-tetragon",
                "tetra",
                "--timeout=40s",
                "tp",
                "add",
                remote,
            ],
            timeout=45,
        )


def remove_policy(name):
    if not re.fullmatch(r"agentguard-[a-f0-9]{32}", name):
        raise ValueError("Exact managed policy identity required")
    with policy_lock():
        command(["docker", "exec", "agentguard-tetragon", "tetra", "tp", "delete", name], timeout=5)
