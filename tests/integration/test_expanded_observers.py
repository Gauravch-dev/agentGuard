"""Negative source semantics tests; these are simulations, not live acceptance."""

import copy
import json
import os
import sys

import pytest

from agentguard.hook_policy import prebirth_policy
from agentguard.prebirth import is_witness
from agentguard.sensors import MappingError, TetragonNormalizer, Workload
from agentguard.source_time import nanoseconds
from application.member2_bridge import translate_member2_event
from tests.integration.test_live_observers import hook_fixture, normalizer


def test_sub_microsecond_reversal_cannot_be_hidden_by_datetime_truncation():
    raw = {
        "time": "2026-10-25T05:54:01.123456100Z",
        "process_exec": {
            "process": {
                "docker": "a" * 64,
                "pid": 1,
                "start_time": "2026-10-25T05:54:01.123456900Z",
            }
        },
    }
    workload = Workload("a" * 64, "cg", "T", 1, "capsule", "host", "2026-10-25T05:54:00Z")
    with pytest.raises(MappingError):
        TetragonNormalizer("source", [workload]).normalize(raw, "private:raw")
    raw = hook_fixture()
    raw["time"] = "2026-10-25T05:54:01.123456100Z"
    raw["process_kprobe"]["process"]["start_time"] = "2026-10-25T05:54:01.123456900Z"
    with pytest.raises(MappingError):
        normalizer().normalize(raw, "private:raw")


def test_exact_source_time_supports_offsets_without_float_rounding():
    assert nanoseconds("2026-10-25T05:54:01.123456789Z") == nanoseconds(
        "2026-10-25T11:24:01.123456789+05:30"
    )
    assert (
        nanoseconds("2026-10-25T05:54:01.123456790Z")
        - nanoseconds("2026-10-25T05:54:01.123456789Z")
        == 1
    )
    for invalid in ("2026-10-25T05:54:01", "2026-10-25T05:54:01.1234567891Z", None):
        with pytest.raises(ValueError):
            nanoseconds(invalid)


def test_canary_witness_requires_explicit_root_identity_and_exact_private_resource():
    source = {"uid": 0, "binary": "/private/probe"}
    raw = {"process_exec": {"process": source}}
    assert is_witness("process", raw, "/private/probe", "/private/ready", "policy")
    for invalid in (None, False, "0", 65532):
        source["uid"] = invalid
        assert not is_witness("process", raw, "/private/probe", "/private/ready", "policy")
    del source["uid"]
    assert not is_witness("process", raw, "/private/probe", "/private/ready", "policy")
    source["uid"] = 0
    assert not is_witness("process", raw, "/foreign/probe", "/private/ready", "policy")
    raw = {
        "process_kprobe": {
            "process": source,
            "function_name": "__x64_sys_openat",
            "policy_name": "policy",
            "args": [{"string_arg": "/private/ready"}],
            "return": {"long_arg": "5"},
        }
    }
    assert is_witness("hooks", raw, "/private/probe", "/private/ready", "policy")
    for invalid in (False, None, -1, "-13", "9999999999999999999"):
        raw["process_kprobe"]["return"]["long_arg"] = invalid
        assert not is_witness("hooks", raw, "/private/probe", "/private/ready", "policy")


@pytest.mark.parametrize(
    "function,returned,effect",
    [
        ("vfs_read", 17, "observed"),
        ("vfs_iter_read", 0, "attempted"),
        ("vfs_write", -13, "attempted"),
        ("security_file_permission", 0, "attempted"),
        ("security_mmap_file", 0, "attempted"),
        ("sock_sendmsg", 5, "observed"),
        ("sock_sendmsg", -101, "attempted"),
        ("sock_recvmsg", 0, "attempted"),
    ],
)
def test_hook_effect_never_confuses_permission_or_zero_bytes_with_io(function, returned, effect):
    raw = hook_fixture()
    body = raw["process_kprobe"]
    body["function_name"] = function
    is_socket = function.startswith("sock_")
    is_int = is_socket or function.startswith("security_")
    body["return"] = {"int_arg": returned} if is_int else {"long_arg": str(returned)}
    body["args"] = (
        [{"sock_arg": {"family": "AF_INET", "daddr": "127.0.0.1", "dport": 49191}}]
        if is_socket
        else [{"file_arg": {"path": "/etc/os-release"}}]
    )
    value = normalizer().normalize(raw, "private:source")
    event, _ = translate_member2_event(value, "hooks-test")
    assert event.effect_status == effect
    assert event.event_type != "egress_flow"
    assert event.coverage_status == "partial"
    altered = copy.deepcopy(value)
    altered["effect_status"] = "completed"
    with pytest.raises(PermissionError):
        translate_member2_event(altered, "hooks-test")


def test_prebirth_policy_excludes_sensor_and_observer_namespaces_and_bounds_canary():
    policy = prebirth_policy("agentguard-" + "a" * 32, "/private/canary", 900, 901)
    for hook in policy["spec"]["kprobes"]:
        selectors = hook["selectors"]
        assert set(selectors[0]["matchNamespaces"][0]["values"]) == {"host_ns", "900", "901"}
        assert len(selectors) == (2 if hook["call"] == "sys_openat" else 1)
    with pytest.raises(ValueError):
        prebirth_policy("agentguard-" + "a" * 32, "/private/canary", None, 901)


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Trusted Linux host lease required",
)
def test_concurrent_policy_mutation_requires_exclusive_kernel_lease(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from agentguard.policy_control import policy_lock

    def competing():
        with policy_lock(tmp_path / "policy-lock", seconds=0.05):
            pytest.fail("Concurrent policy mutation was allowed")

    with policy_lock(tmp_path / "policy-lock"):
        with ThreadPoolExecutor(max_workers=1) as worker:
            future = worker.submit(competing)
            with pytest.raises(TimeoutError):
                future.result(timeout=2)
    with policy_lock(tmp_path / "policy-lock", seconds=0.05):
        pass  # The lease is released after the first owner closes its FD.


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="Root-private Linux policy files required",
)
def test_wrong_policy_identity_or_shared_file_cannot_reach_docker(tmp_path, monkeypatch):
    from agentguard import policy_control
    from agentguard.capsules import private_directory

    root = private_directory(tmp_path / "policies")
    policy = root / "policy.json"
    policy.write_text(json.dumps({"metadata": {"name": "foreign-policy"}}))
    policy.chmod(0o600)
    calls = []
    monkeypatch.setattr(policy_control, "command", lambda args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        policy_control.install_policy(policy, "agentguard-" + "a" * 32)
    policy.chmod(0o644)
    with pytest.raises(PermissionError):
        policy_control.install_policy(policy, "agentguard-" + "a" * 32)
    for invalid in ("foreign-policy", "agentguard-../../host", "--all"):
        with pytest.raises(ValueError):
            policy_control.remove_policy(invalid)
    assert calls == []
