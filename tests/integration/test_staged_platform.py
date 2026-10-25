"""Security regressions for staging; actual container experiments are separate."""

import copy
import os
import sys
import time
from pathlib import Path

import pytest

from agentguard.authority import sample_contract
from agentguard.capsules import (
    RuntimeRecord,
    deadline_reached,
    private_directory,
    publish_admission,
)
from agentguard.platform import PlatformError, verify_inspect
from agentguard.schema import timestamp
from agentguard.sensors import MappingError, TetragonNormalizer, Workload
from scripts.linux_live_lab import COUNTERS, counter_deltas
from tests import test_security as upstream_tests


def test_staged_mount_must_be_one_read_only_private_channel():
    fixture = upstream_tests.RuntimeTests()
    fixture.setUp()
    info = copy.deepcopy(fixture.info)
    directory = Path("/run/agentguard/channels/capsule-reviewed")
    entrypoint = ["python", "-I", "/opt/agentguard/admission.py"]
    info["Config"]["Entrypoint"] = entrypoint
    info["HostConfig"]["Mounts"] = [{"Type": "bind"}]
    mount = {
        "Type": "bind",
        "Source": str(directory),
        "Destination": "/run/agentguard",
        "RW": False,
        "Propagation": "rprivate",
    }
    info["Mounts"] = [mount]
    assert not verify_inspect(
        info, fixture.contract, fixture.image, capsule_mount=directory, entrypoint=entrypoint
    )
    for field, bad_value in (
        ("RW", True),
        ("Propagation", "rshared"),
        ("Source", "/"),
        ("Destination", "/var/run/docker.sock"),
    ):
        changed = copy.deepcopy(info)
        changed["Mounts"][0][field] = bad_value
        assert verify_inspect(
            changed, fixture.contract, fixture.image, capsule_mount=directory, entrypoint=entrypoint
        )


def test_missing_or_reset_sensor_counters_are_not_zero_loss():
    before = {"counters": dict.fromkeys(COUNTERS, 2)}
    after = {"counters": dict.fromkeys(COUNTERS, 2)}
    after["counters"][COUNTERS[0]] = None
    after["counters"][COUNTERS[1]] = 0
    after["counters"][COUNTERS[2]] = 5
    deltas = counter_deltas(before, after)
    assert deltas[COUNTERS[0]]["delta"] is None
    assert deltas[COUNTERS[1]]["status"] == "unknown_or_reset"
    assert deltas[COUNTERS[2]]["delta"] == 3


def test_conflicting_source_times_remain_an_attribution_gap():
    # Sanitized timestamps from a real pinned-sensor capture, preserved exactly.
    raw = {
        "time": "2026-10-24T16:26:47.778417931Z",
        "process_exec": {
            "process": {
                "docker": "a" * 64,
                "pid": 31888,
                "binary": "/usr/local/bin/python",
                "start_time": "2026-10-24T16:26:47.778418322Z",
            }
        },
    }
    original = copy.deepcopy(raw)
    workload = Workload(
        "a" * 64, "cg-lab", "LAB", 1, "capsule-lab", "linux-lab-01", "2026-10-24T16:26:40Z"
    )
    with pytest.raises(MappingError):
        TetragonNormalizer("process-lab", [workload]).normalize(raw, "protected-raw:timestamp-gap")
    assert raw == original


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="private root-owned Linux runtime state required",
)
def test_runtime_record_round_trip_and_symlink_rejection(tmp_path):
    directory = private_directory(tmp_path / "runtime")
    record = RuntimeRecord(directory / ("capsule-" + "a" * 32 + ".json"))
    value = {"state": "staged", "deadline": timestamp()}
    with record.lock():
        record.write(value)
        assert record.read() == value
    record.path.unlink()
    record.path.symlink_to(directory / "outside")
    with pytest.raises(OSError):
        record.read()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux boot/monotonic identity required")
def test_monotonic_expiry_and_boot_change_cannot_extend_deadline():
    contract = sample_contract()
    value = {
        "deadline": contract["expires_at"],
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "monotonic_deadline": time.monotonic() + 60,
    }
    assert not deadline_reached(value)
    value["monotonic_deadline"] = 0
    assert deadline_reached(value)
    value["monotonic_deadline"] = time.monotonic() + 60
    value["boot_id"] = "a-different-boot"
    assert deadline_reached(value)


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="rootful Linux directory ownership required",
)
def test_runtime_state_rejects_shared_directory(tmp_path):
    path = tmp_path / "shared"
    path.mkdir(mode=0o755)
    with pytest.raises(PlatformError):
        private_directory(path)


@pytest.mark.skipif(
    sys.platform != "linux", reason="Linux admission-file permission semantics required"
)
def test_admission_marker_is_complete_readable_and_exclusive_under_private_umask(tmp_path):
    previous = os.umask(0o077)
    try:
        publish_admission(tmp_path)
    finally:
        os.umask(previous)
    marker = tmp_path / "admitted"
    assert marker.read_bytes() == b"admitted-v1\n"
    assert marker.stat().st_mode & 0o777 == 0o444
    with pytest.raises(FileExistsError):
        publish_admission(tmp_path)
    assert list(tmp_path.iterdir()) == [marker]
