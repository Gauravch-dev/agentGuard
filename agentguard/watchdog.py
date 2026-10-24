"""Independent, durable deadline monitor for a launcher-owned staged capsule."""

import fcntl
import os
import sys
import time
from pathlib import Path

from .capsules import RuntimeRecord, contain_record, deadline_reached
from .platform import DockerLab


def watch(path: Path):
    record = RuntimeRecord(path)
    parent = path.parent.stat()
    if os.geteuid() != 0 or parent.st_uid != 0 or parent.st_mode & 0o077:
        raise PermissionError("private root-owned runtime state required")
    descriptor = os.open(path.with_suffix(".watch"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        while True:
            with record.lock():
                value = record.read()
            if value["state"] == "contained":
                return
            try:
                if value["requested_stop"] or deadline_reached(value):
                    contain_record(record)
                    return
                live = DockerLab().inspect(value["container_id"])
                if live["State"].get("Status") in {"exited", "dead"}:
                    if value.get("identity") is None:
                        with record.lock():
                            current = record.read()
                            current.update(
                                state="containment_unverified",
                                descendants_exited=False,
                                last_watchdog_error="missing_initial_cgroup_identity",
                            )
                            record.write(current)
                        return
                    contain_record(record)
                    return
            except Exception as exc:
                # Keep retrying containment across daemon outages. Do not silently
                # turn an unavailable runtime into a successful lifecycle result.
                with record.lock():
                    current = record.read()
                    current.update(requested_stop=True, last_watchdog_error=type(exc).__name__)
                    record.write(current)
                if current.get("identity") is None:
                    try:
                        terminal = DockerLab().inspect(current["container_id"])["State"]
                        if terminal.get("Status") in {"exited", "dead"}:
                            with record.lock():
                                current = record.read()
                                current.update(
                                    state="containment_unverified", descendants_exited=False
                                )
                                record.write(current)
                            return
                    except Exception as inspection_error:
                        with record.lock():
                            current = record.read()
                            current["last_inspection_error"] = type(inspection_error).__name__
                            record.write(current)
            time.sleep(0.2)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    watch(Path(sys.argv[1]))
