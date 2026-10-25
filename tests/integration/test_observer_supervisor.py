"""Explicit transport/health simulations, not genuine sensor coverage evidence."""

import threading
import time
from types import SimpleNamespace

import pytest

from agentguard import supervisor
from agentguard.observer_health import SourceHealth, clock_compatible, health_reasons, metric_delta
from agentguard.supervisor import ObserverWorker


def test_missing_reset_or_changed_counter_series_never_proves_zero_loss():
    assert metric_delta({"lost": 5}, {"lost": 8}) == (3, False)
    assert metric_delta({"lost": 5}, {"lost": 0}) == (None, True)
    assert metric_delta({"lost": None}, {"lost": None}) == (None, False)
    assert metric_delta({"lost": 0}, {"lost": 0, "another": 0}) == (None, True)


def test_source_eof_stale_health_and_pending_export_all_hold():
    sources = {
        "process": SourceHealth(True, 1, lost=None),
        "hooks": SourceHealth(False, 10, lost=0),
        "packet": SourceHealth(True, 10, pending=1, gaps=1, lost=2, epoch_changed=True),
    }
    reasons = health_reasons(sources, 10)
    assert {
        "PROCESS_HEALTH_STALE",
        "PROCESS_LOSS_ACCOUNTING_UNKNOWN",
        "HOOKS_SOURCE_UNAVAILABLE",
        "PACKET_EXPORT_PENDING",
        "PACKET_SOURCE_GAPS",
        "PACKET_EVENT_LOSS",
        "PACKET_SOURCE_EPOCH_CHANGED",
    } <= set(reasons)


def test_host_clock_step_does_not_become_a_healthy_interval():
    assert clock_compatible(100, 10, 102, 12)
    assert not clock_compatible(100, 10, 92, 12)
    assert not clock_compatible(100, 10, 100, 9)


def test_reused_pid_is_rejected_before_a_policy_can_attach_to_another_namespace(monkeypatch):
    value = {
        "identity": {"pid": 123, "start_ticks": "10", "cgroup": "/capsule", "cgroup_inode": 456}
    }
    monkeypatch.setattr(
        supervisor,
        "process_identity",
        lambda pid: {"pid": pid, "start_ticks": "99", "cgroup": "/foreign"},
    )
    with pytest.raises(PermissionError):
        supervisor.verified_mount_namespace(value)


def test_sensor_ingestion_budget_cannot_be_obtained_by_invalid_token_rotation(stack):
    app, client, settings, runtime = stack
    source = settings.sensors["lab-sensor"]
    key, budget = settings.rate_bucket("loopback", "/internal/v1/events", "Bearer " + source.token)
    assert budget == 10000 and key != "loopback"
    for token in ("invalid-one", "invalid-two", settings.owner_token):
        assert settings.rate_bucket("loopback", "/internal/v1/events", "Bearer " + token) == (
            "loopback",
            600,
        )
    assert settings.rate_bucket("loopback", "/api/v1/tasks", "Bearer " + source.token) == (
        "loopback",
        600,
    )


def test_healthy_transport_cannot_erase_scope_start_or_clock_semantic_gaps():
    worker = ObserverWorker.__new__(ObserverWorker)
    worker.lock = threading.Lock()
    worker.sources = {
        kind: SourceHealth(True, time.monotonic(), lost=0)
        for kind in ("process", "hooks", "packet")
    }
    worker.errors = set()
    worker.last_check = time.monotonic()
    worker.finished = False
    worker.epoch = "test-epoch"
    worker.binding = SimpleNamespace(capsule_id="fixture-capsule")
    worker.value = {"identity": {"cgroup_inode": 123}}
    worker.restarts = {kind: 0 for kind in worker.sources}
    status = worker.snapshot()
    assert {
        "BOOTSTRAP_OBSERVATION_START_GAP",
        "FILE_AND_NETWORK_HOOK_SCOPE_PARTIAL",
        "NETWORK_PROCESS_ATTRIBUTION_UNAVAILABLE",
        "SOURCE_CLOCK_SEMANTICS_UNVERIFIED",
    } <= set(status["reasons"])
    assert status["protected_execution_ready"] is False
