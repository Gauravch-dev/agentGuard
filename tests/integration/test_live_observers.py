"""Sanitized source shapes and simulations, never substitutes for live evidence."""

import copy
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from agentguard.admission_review import LiveAdmissionReview
from agentguard.hook_policy import HookNormalizer
from agentguard.network_tap import packet_metadata
from agentguard.sensors import MappingError, Workload
from application.member2_bridge import translate_member2_event
from scripts.linux_sensor_registry import create
from scripts.start_linux import load_sensor_registry


def hook_fixture():
    return {
        "time": "2026-10-25T05:54:02Z",
        "process_kprobe": {
            "policy_name": "agentguard-" + "a" * 32,
            "function_name": "__x64_sys_connect",
            "process": {
                "docker": "a" * 64,
                "pid": 123,
                "start_time": "2026-10-25T05:54:01Z",
                "arguments": "PRIVATE-ARGUMENT",
            },
            "args": [{"sockaddr_arg": {"family": "AF_INET", "addr": "192.0.2.1", "port": 443}}],
            "return": {"long_arg": "-101"},
        },
    }


def normalizer():
    workload = Workload(
        "a" * 64, "cg-test", "TASK", 1, "capsule-test", "test-host", "2026-10-25T05:54:00Z"
    )
    return HookNormalizer("hooks-test", [workload], ["agentguard-" + "a" * 32])


def test_failed_connect_observation_is_never_enforcement_or_flow_proof():
    raw = hook_fixture()
    original = copy.deepcopy(raw)
    value = normalizer().normalize(raw, "tetragon:test")
    event, metadata = translate_member2_event(value, "hooks-test")
    assert event.event_type == "connection_attempt"
    assert event.policy_verdict == "unknown"
    assert event.effect_status == "attempted"
    assert event.coverage_status == "partial"
    assert metadata["details"]["kernel_return"] == -101
    assert "PRIVATE-ARGUMENT" not in json.dumps(value)
    assert raw == original
    for field, invalid in (
        ("coverage_status", "complete"),
        ("policy_verdict", "denied"),
        ("effect_status", "blocked"),
    ):
        altered = copy.deepcopy(value)
        altered[field] = invalid
        with pytest.raises(PermissionError):
            translate_member2_event(altered, "hooks-test")


@pytest.mark.parametrize(
    "field,invalid", [("docker", "b" * 64), ("start_time", "2026-10-25T05:54:03Z"), ("pid", None)]
)
def test_hook_identity_ambiguity_remains_a_gap(field, invalid):
    raw = hook_fixture()
    raw["process_kprobe"]["process"][field] = invalid
    with pytest.raises(MappingError):
        normalizer().normalize(raw, "tetragon:test")


def test_unapproved_hook_policy_cannot_supply_observation():
    raw = hook_fixture()
    raw["process_kprobe"]["policy_name"] = "unreviewed"
    with pytest.raises(MappingError):
        normalizer().normalize(raw, "tetragon:test")


def test_packet_metadata_never_retains_application_payload():
    payload = b"PRIVATE-PAYLOAD"
    ipv4 = bytearray(20)
    ipv4[0], ipv4[9] = 0x45, 17
    ipv4[12:16] = bytes([127, 0, 0, 1])
    ipv4[16:20] = bytes([127, 0, 0, 1])
    frame = b"\x00" * 12 + b"\x08\x00" + ipv4 + payload
    metadata = packet_metadata(frame, ("lo", 0, 4))
    assert metadata["destination_scope"] == "loopback"
    assert metadata["packet_type"] == 4
    assert "PRIVATE" not in json.dumps(metadata)
    assert "pid" not in metadata
    with pytest.raises(ValueError):
        packet_metadata(b"short", ("lo", 0, 4))


def test_missing_live_review_proof_cannot_approve_even_a_well_formed_record():
    # No controller/kernel double: a missing trusted provider must refuse cleanly.
    review = LiveAdmissionReview(None, None)
    assert review({}) is False
    assert review.last_reasons == ["LIVE_PLATFORM_REVIEW_UNAVAILABLE"]


def test_concurrent_admission_diagnostics_cannot_change_another_capsule_decision():
    rejected_ready, accepted_done = threading.Event(), threading.Event()

    class ConcurrentReview(LiveAdmissionReview):
        @property
        def last_reasons(self):
            return self.diagnostic

        @last_reasons.setter
        def last_reasons(self, reasons):
            self.diagnostic = reasons
            if reasons:
                rejected_ready.set()
                assert accepted_done.wait(3)
            elif rejected_ready.is_set():
                accepted_done.set()

        def reasons(self, value):
            return ["CURRENT_EFFECTIVE_PROFILE_REFUSED"] if value["reject"] else []

    review = ConcurrentReview(None, None)
    with ThreadPoolExecutor(max_workers=1) as executor:
        rejected = executor.submit(review, {"reject": True})
        assert rejected_ready.wait(3)
        assert review({"reject": False}) is True
        assert rejected.result(timeout=3) is False


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Root-private Linux registry required",
)
def test_private_sensor_registry_is_distinct_and_does_not_rotate_on_restart(tmp_path):
    root = tmp_path / "registry"
    path = create(root, "test-host")
    first = load_sensor_registry(path, "test-host")
    assert len({source.token for source in first.values()}) == 3
    assert first["linux-packet-01"].sources == ("network_sensor", "sensor_health")
    assert create(root, "test-host") == path
    assert load_sensor_registry(path, "test-host") == first
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        load_sensor_registry(path, "test-host")


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Root-private Linux registry required",
)
def test_sensor_registry_cannot_register_broker_or_other_host(tmp_path):
    path = create(tmp_path / "registry", "test-host")
    records = json.loads(path.read_text())
    records["linux-hooks-01"]["sources"] = ["trusted_broker"]
    path.write_text(json.dumps(records))
    with pytest.raises(ValueError):
        load_sensor_registry(path, "test-host")
