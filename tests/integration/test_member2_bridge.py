"""Cross-project interface tests. All generated telemetry/OS identities here are fixtures."""

import json
import struct
from datetime import timedelta
from uuid import uuid4

import pytest

from agentguard.hook_policy import HookNormalizer
from agentguard.platform import Check
from agentguard.schema import validate_contract
from agentguard.sensors import Workload
from application.brokers import ChannelContext
from application.coverage import release_coverage_ready
from application.member2_bridge import (
    Member2ChannelAuthorizer,
    Member2RuntimeAdapter,
    normalize_tetragon,
)
from application.models import Coverage, TaskContract, now
from application.synthetic import department_totals
from tests.unit.test_brokers_authority import call


def upstream_process(binding, sensor_id="lab-sensor"):
    workload = Workload(
        "a" * 64,
        binding.cgroup_id,
        binding.task_id,
        binding.contract_version,
        binding.capsule_id,
        binding.host_id,
        binding.process_start.isoformat(),
    )
    raw = {
        "time": now().isoformat(),
        "process_exec": {
            "process": {
                "docker": "a" * 12,
                "pid": 234,
                "binary": "/usr/bin/python",
                "arguments": "PRIVATE-ARGUMENT-MUST-NOT-BE-LOGGED",
                "start_time": now().isoformat(),
            }
        },
    }
    # Source time must not predate process birth.
    raw["time"] = now().isoformat()
    event, metadata = normalize_tetragon(raw, "protected-file:offset-20", sensor_id, [workload])
    value = event.model_dump(mode="json") | {
        "received_at": metadata["collector_received_at"],
        "details": metadata["details"],
    }
    return value


def test_contract_is_accepted_by_both_members(running):
    (app, client, settings, runtime), task, headers = running
    assert validate_contract(task) == TaskContract.model_validate(task).model_dump(mode="json")


def test_member2_process_reaches_authenticated_api_without_changing_shared_schema(running):
    (app, client, settings, runtime), task, headers = running
    value = upstream_process(runtime.binding)
    payload = {"wire_format": "member2-normalized-1.0", "event": value}
    sensor = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    assert (
        client.post("/internal/v1/member2/events", json=payload, headers=headers).status_code == 403
    )
    response = client.post("/internal/v1/member2/events", json=payload, headers=sensor)
    assert response.status_code == 200, response.text
    assert response.json()["duplicate"] is False
    # Collector receipt time can change on replay; source identity/event remains stable.
    payload["event"]["received_at"] = now().isoformat()
    assert (
        client.post("/internal/v1/member2/events", json=payload, headers=sensor).json()["duplicate"]
        is True
    )
    row = app.state.store.evidence(task["task_id"], "event")[0]["body"]
    assert "details" not in row["event"] and "received_at" not in row["event"]
    assert row["event"]["observed_at"] == value["observed_at"]
    assert row["received_at"]
    metadata = app.state.store.evidence(task["task_id"], "member2_metadata")[0]["body"]
    assert metadata["details"]["sensor_id"] == "lab-sensor"
    assert "PRIVATE-ARGUMENT" not in json.dumps(app.state.store.evidence(task["task_id"]))
    result = client.get(f"/api/v1/tasks/{task['task_id']}/result", headers=headers).json()
    assert any(f["reason_code"] == "EVENT_COVERAGE_LIMITED" for f in result["findings"])


@pytest.mark.parametrize("mutation", ["sensor", "harness", "broker", "extra"])
def test_member2_bridge_rejects_untrusted_extensions(running, mutation):
    (app, client, settings, runtime), task, headers = running
    value = upstream_process(runtime.binding)
    if mutation == "sensor":
        value["details"]["sensor_id"] = "different"
    if mutation == "harness":
        value["details"]["execution_mode"] = "policy-harness"
    if mutation == "broker":
        value["source"] = "trusted_broker"
    if mutation == "extra":
        value["unexpected"] = "never silently dropped"
    sensor = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    response = client.post(
        "/internal/v1/member2/events",
        json={"wire_format": "member2-normalized-1.0", "event": value},
        headers=sensor,
    )
    assert response.status_code in {403, 409}
    assert not app.state.store.evidence(task["task_id"], "event")


def test_json_duplicate_keys_rejected_before_authorization(stack):
    app, client, settings, runtime = stack
    headers = {
        "Authorization": f"Bearer {settings.owner_token}",
        "Content-Type": "application/json",
    }
    response = client.post(
        "/api/v1/tasks",
        content='{"template_id":"finance_summary_v1","template_id":"finance_summary_v1"}',
        headers=headers,
    )
    assert response.status_code == 422


class ProbeOnlyLab:
    """Test double proving passing probes cannot enable arbitrary agent execution."""

    def __init__(self):
        self.protected = None
        self.ran = False

    def preflight(self, *, protected=False):
        self.protected = protected
        return [Check("fixture_all_probes", "passed", "TEST ONLY")]

    def isolation_lab(self, contract, image):
        self.ran = True
        return {"mode": "isolation-lab", "protected_mvp_complete": False}


def test_adapter_keeps_protected_gate_even_when_probe_preflight_passes(stack):
    app, client, settings, runtime = stack
    lab = ProbeOnlyLab()
    adapter = Member2RuntimeAdapter(lab, approved_image="sha256:" + "a" * 64)
    contract = app.state.authority.create("synthetic-finance-owner")
    result = adapter.launch(contract)
    assert lab.protected is True
    assert not lab.ran
    assert result.readiness_passed is False and result.binding is None
    assert adapter.isolation_lab(contract)["mode"] == "isolation-lab"


def test_platform_api_is_real_readonly_preflight_and_launch_fails_closed(tmp_path):
    import secrets

    from fastapi.testclient import TestClient

    from application.api import create_app
    from application.config import Settings

    settings = Settings(
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        database=tmp_path / "db.sqlite3",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {settings.owner_token}"}
        assert client.get("/api/v1/platform").status_code == 403
        platform = client.get("/api/v1/platform", headers=headers).json()
        assert platform["preflight"]["protected_execution_ready"] is False
        task = client.post("/api/v1/tasks", json={}, headers=headers).json()["contract"]
        assert (
            client.post(
                f"/api/v1/tasks/{task['task_id']}/isolation-lab", headers=headers
            ).status_code
            == 503
        )
        assert app.state.authority.record(task["task_id"])["state"] == "approved"
        assert (
            client.post(f"/api/v1/tasks/{task['task_id']}/launch", headers=headers).status_code
            == 503
        )
        assert app.state.store.evidence(task["task_id"], "platform_preflight")
    app.state.store.db.close()


def test_output_holds_when_live_coverage_missing(running):
    (app, client, settings, runtime), task, headers = running
    app.state.broker.coverage_check = app.state.coverage_policy
    response = call(
        app, runtime, "output.save_department_summary", department_totals().model_dump(mode="json")
    )
    assert response.receipt.reason == "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE"
    assert response.receipt.effect_status == "blocked"
    assert not app.state.store.evidence(task["task_id"], "report")


def test_release_coverage_requires_all_scopes_freshness_and_no_loss(running):
    (app, client, settings, runtime), task, headers = running
    binding = runtime.binding
    start = binding.process_start
    end = now()
    windows = [
        Coverage(
            coverage_id=uuid4().hex,
            task_id=binding.task_id,
            capsule_id=binding.capsule_id,
            sensor_id="fixture-sensor",
            source=source,
            event_classes=classes,
            start=start,
            end=end,
            status="complete",
        )
        for source, classes in [
            ("host_sensor", ("process_exec", "file_access", "connection_attempt")),
            ("network_sensor", ("egress_flow",)),
        ]
    ]
    assert release_coverage_ready(binding, windows, start, end, end + timedelta(seconds=1))
    assert not release_coverage_ready(binding, windows, start, end, end + timedelta(seconds=10))
    assert not release_coverage_ready(binding, windows[:1], start, end, end + timedelta(seconds=1))
    windows[0] = windows[0].model_copy(update={"lost_events": 1})
    assert not release_coverage_ready(binding, windows, start, end, end + timedelta(seconds=1))


@pytest.mark.parametrize("status,lost", [("partial", 0), ("complete", 1)])
def test_known_recent_outage_after_last_broker_action_still_holds_output(running, status, lost):
    (app, client, settings, runtime), task, headers = running
    binding = runtime.binding
    cutoff = now()
    windows = [
        Coverage(
            coverage_id=uuid4().hex,
            task_id=binding.task_id,
            capsule_id=binding.capsule_id,
            sensor_id="fixture-sensor",
            source=source,
            event_classes=classes,
            start=binding.process_start,
            end=cutoff,
            status="complete",
        )
        for source, classes in (
            ("host_sensor", ("process_exec", "file_access", "connection_attempt")),
            ("network_sensor", ("egress_flow",)),
        )
    ]
    checked = cutoff + timedelta(seconds=1)
    assert release_coverage_ready(binding, windows, binding.process_start, cutoff, checked)
    windows.append(
        Coverage(
            coverage_id=uuid4().hex,
            task_id=binding.task_id,
            capsule_id=binding.capsule_id,
            sensor_id="fixture-sensor",
            source="network_sensor",
            event_classes=("egress_flow",),
            start=cutoff + timedelta(milliseconds=100),
            end=checked,
            status=status,
            lost_events=lost,
        )
    )
    assert not release_coverage_ready(binding, windows, binding.process_start, cutoff, checked)


def test_peer_bridge_reuses_upstream_proc_parser_and_rejects_reuse(running, tmp_path, monkeypatch):
    import socket

    # Windows fixture only: this is not the skipped real Linux peer-credential test.
    if not hasattr(socket, "SO_PEERCRED"):
        monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    (app, client, settings, runtime), task, headers = running
    proc = tmp_path / "proc" / "123"
    proc.mkdir(parents=True)
    fields = ["S"] + ["0"] * 18 + ["987654"] + ["0"] * 4
    (proc / "stat").write_text("123 (fixture ) process) " + " ".join(fields))
    (proc / "cgroup").write_text("0::/lab/capsule\n")
    group = tmp_path / "cgroup" / "lab" / "capsule"
    group.mkdir(parents=True)
    kwargs = dict(proc_root=tmp_path / "proc", cgroup_root=tmp_path / "cgroup")
    authorizer = Member2ChannelAuthorizer(
        app.state.broker, runtime.binding, "/lab/capsule", 987000, group.stat().st_ino, **kwargs
    )

    class FixtureSocket:
        def getsockopt(self, *args):
            return struct.pack("3i", 123, 65532, 65532)

    assert authorizer.authorize(FixtureSocket()) == ChannelContext(
        runtime.binding.channel_id, runtime.binding.capsule_id
    )
    reused = Member2ChannelAuthorizer(
        app.state.broker, runtime.binding, "/lab/capsule", 999999, group.stat().st_ino, **kwargs
    )
    with pytest.raises(PermissionError):
        reused.authorize(FixtureSocket())
    replaced = Member2ChannelAuthorizer(
        app.state.broker, runtime.binding, "/lab/capsule", 987000, group.stat().st_ino + 1, **kwargs
    )
    with pytest.raises(PermissionError):
        replaced.authorize(FixtureSocket())
    app.state.authority.transition(task["task_id"], "failed")
    with pytest.raises((PermissionError, ValueError)):
        authorizer.authorize(FixtureSocket())


def test_authenticated_coverage_unblocks_internal_release_only_with_new_request(running):
    (app, client, settings, runtime), task, headers = running
    app.state.broker.coverage_check = app.state.coverage_policy
    report = department_totals().model_dump(mode="json")
    denied = call(app, runtime, "output.save_department_summary", report, "held-1")
    assert denied.receipt.reason == "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE"
    call(app, runtime, "data.get_department_totals", request_id="totals-1")
    sensor = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    for source, classes in [
        ("host_sensor", ("process_exec", "file_access", "connection_attempt")),
        ("network_sensor", ("egress_flow",)),
    ]:
        window = Coverage(
            coverage_id=uuid4().hex,
            task_id=task["task_id"],
            capsule_id=runtime.binding.capsule_id,
            sensor_id="lab-sensor",
            source=source,
            event_classes=classes,
            start=runtime.binding.process_start,
            end=now(),
            status="complete",
        )
        response = client.post(
            "/internal/v1/coverage", json=window.model_dump(mode="json"), headers=sensor
        )
        assert response.status_code == 200
    # The old decision is immutable; retry with a fresh per-request identity.
    assert call(app, runtime, "output.save_department_summary", report, "held-1") == denied
    released = call(app, runtime, "output.save_department_summary", report, "release-2")
    assert released.receipt.effect_status == "completed"
    assert len(app.state.store.evidence(task["task_id"], "report")) == 1
    assert app.state.authority.record(task["task_id"])["state"] == "running"


def test_fixed_lab_route_rejects_caller_runtime_options(stack):
    app, client, settings, runtime = stack
    headers = {"Authorization": f"Bearer {settings.owner_token}"}
    task = client.post("/api/v1/tasks", json={}, headers=headers).json()["contract"]
    response = client.post(
        f"/api/v1/tasks/{task['task_id']}/isolation-lab",
        json={"image": "unreviewed", "mount": "/"},
        headers=headers,
    )
    assert response.status_code == 422


def test_capture_forwarder_is_local_authenticated_and_never_promotes_coverage(monkeypatch, running):
    import io

    import httpx

    from application.member2_exporter import forward_capture

    (app, client, settings, runtime), task, headers = running
    binding = runtime.binding
    workload = Workload(
        "a" * 64,
        binding.cgroup_id,
        binding.task_id,
        1,
        binding.capsule_id,
        binding.host_id,
        binding.process_start.isoformat(),
    )
    raw = {
        "time": now().isoformat(),
        "process_exec": {
            "process": {
                "docker": "a" * 12,
                "pid": 234,
                "binary": "/usr/bin/python",
                "start_time": binding.process_start.isoformat(),
            }
        },
    }
    original = httpx.Client

    def receive(request):
        assert str(request.url) == "http://127.0.0.1:8000/internal/v1/member2/events"
        assert request.headers["Authorization"] == f"Bearer {settings.sensors['lab-sensor'].token}"
        body = json.loads(request.content)
        assert body["event"]["coverage_status"] == "partial"
        assert body["wire_format"] == "member2-normalized-1.0"
        return httpx.Response(200, json={"accepted": True, "duplicate": False})

    def factory(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return original(transport=httpx.MockTransport(receive), **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    result = forward_capture(
        io.StringIO(json.dumps(raw) + "\n"),
        [workload],
        "lab-sensor",
        settings.sensors["lab-sensor"].token,
    )
    assert result["forwarded"] == 1
    assert result["coverage_promoted"] is False and result["sensor_health_verified"] is False
    with pytest.raises(ValueError):
        forward_capture(
            io.StringIO("x" * 65537), [workload], "lab-sensor", settings.sensors["lab-sensor"].token
        )


def test_legacy_payroll_fixture_cannot_change_canonical_totals(running):
    from agentguard.brokers import department_summary

    (app, client, settings, runtime), task, headers = running
    response = call(app, runtime, "output.save_department_summary", department_summary())
    assert response.receipt.reason == "TOTALS_MISMATCH"
    assert not app.state.store.evidence(task["task_id"], "report")


def test_changed_replayed_provenance_is_preserved_as_a_conflict(running):
    (app, client, settings, runtime), task, owner = running
    value = upstream_process(runtime.binding)
    sensor = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    payload = {"wire_format": "member2-normalized-1.0", "event": value}
    assert (
        client.post("/internal/v1/member2/events", json=payload, headers=sensor).status_code == 200
    )
    value["details"]["attribution_basis"] = "contradictory-source-map"
    for _ in range(2):
        assert (
            client.post("/internal/v1/member2/events", json=payload, headers=sensor).status_code
            == 409
        )
    conflicts = app.state.store.evidence(task["task_id"], "ingestion_conflict")
    assert len(conflicts) == 1
    assert conflicts[0]["body"]["reason"] == "EVENT_PROVENANCE_CHANGED"
    assert conflicts[0]["body"]["contract_version"] == 1
    original = app.state.store.evidence(task["task_id"], "member2_metadata")[0]["body"]
    assert original["details"]["attribution_basis"] != "contradictory-source-map"
    assert not app.state.coverage_policy(runtime.binding)
    result = client.get(f"/api/v1/tasks/{task['task_id']}/result", headers=owner).json()
    assert "CONFLICTING_DUPLICATE" in {f["reason_code"] for f in result["findings"]}


def test_source_replay_after_adapter_upgrade_preserves_first_metadata(running, monkeypatch):
    (app, client, settings, runtime), task, owner = running
    payload = {"wire_format": "member2-normalized-1.0", "event": upstream_process(runtime.binding)}
    sensor = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    assert (
        client.post("/internal/v1/member2/events", json=payload, headers=sensor).status_code == 200
    )
    original = app.state.store.evidence(task["task_id"], "member2_metadata")[0]["body"]
    monkeypatch.setattr("application.member2_bridge.UPSTREAM_COMMIT", "b" * 40)
    response = client.post("/internal/v1/member2/events", json=payload, headers=sensor)
    assert response.json()["duplicate"] is True
    assert app.state.store.evidence(task["task_id"], "ingestion_conflict") == []
    assert app.state.store.evidence(task["task_id"], "member2_metadata")[0]["body"] == original


def test_conflicting_coverage_holds_release_even_after_fresh_complete_windows(running):
    (app, client, settings, runtime), task, owner = running
    app.state.broker.coverage_check = app.state.coverage_policy
    binding = runtime.binding
    sensor = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    windows = []
    for source, classes in (
        ("host_sensor", ("process_exec", "file_access", "connection_attempt")),
        ("network_sensor", ("egress_flow",)),
    ):
        window = Coverage(
            coverage_id=uuid4().hex,
            task_id=binding.task_id,
            capsule_id=binding.capsule_id,
            sensor_id="lab-sensor",
            source=source,
            event_classes=classes,
            start=binding.process_start,
            end=now(),
            status="complete",
        )
        windows.append(window.model_dump(mode="json"))
        assert (
            client.post("/internal/v1/coverage", json=windows[-1], headers=sensor).status_code
            == 200
        )
    assert app.state.coverage_policy(binding)
    assert client.post("/internal/v1/coverage", json=windows[0], headers=sensor).json()["duplicate"]
    changed = windows[0] | {"lost_events": 1}
    assert client.post("/internal/v1/coverage", json=changed, headers=sensor).status_code == 409
    for window in windows:
        fresh = window | {"coverage_id": uuid4().hex, "end": now().isoformat()}
        assert client.post("/internal/v1/coverage", json=fresh, headers=sensor).status_code == 200
    assert not app.state.coverage_policy(binding)
    denied = call(
        app, runtime, "output.save_department_summary", department_totals().model_dump(mode="json")
    )
    assert denied.receipt.reason == "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE"
    assert app.state.store.evidence(binding.task_id, "report") == []
    assert app.state.store.evidence(binding.task_id, "coverage")[0]["body"]["lost_events"] == 0


def test_conflict_from_old_revision_remains_audit_only(running):
    (app, client, settings, runtime), task, owner = running
    value = upstream_process(runtime.binding)
    payload = {"wire_format": "member2-normalized-1.0", "event": value}
    sensor = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    assert (
        client.post("/internal/v1/member2/events", json=payload, headers=sensor).status_code == 200
    )
    value["resource_or_destination"] = "changed-source-resource"
    assert (
        client.post("/internal/v1/member2/events", json=payload, headers=sensor).status_code == 409
    )
    app.state.authority.transition(task["task_id"], "failed")
    assert (
        client.post(f"/api/v1/tasks/{task['task_id']}/revisions", headers=owner).status_code == 201
    )
    result = client.get(f"/api/v1/tasks/{task['task_id']}/result", headers=owner).json()
    assert "CONFLICTING_DUPLICATE" not in {f["reason_code"] for f in result["findings"]}
    assert len(app.state.store.evidence(task["task_id"], "ingestion_conflict")) == 1


def test_real_hook_shape_reconciles_as_attempt_without_enforcement_claim(running):
    from tests.integration.test_live_observers import hook_fixture

    (app, client, settings, runtime), task, owner = running
    binding = runtime.binding
    workload = Workload(
        "a" * 64,
        binding.cgroup_id,
        binding.task_id,
        1,
        binding.capsule_id,
        binding.host_id,
        binding.process_start.isoformat(),
    )
    raw = hook_fixture()
    raw["process_kprobe"]["process"]["start_time"] = binding.process_start.isoformat()
    raw["time"] = now().isoformat()
    value = HookNormalizer(
        "lab-sensor", [workload], [raw["process_kprobe"]["policy_name"]]
    ).normalize(raw, "protected-hook:fixture")
    sensor = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    response = client.post(
        "/internal/v1/member2/events",
        json={"wire_format": "member2-normalized-1.0", "event": value},
        headers=sensor,
    )
    assert response.status_code == 200, response.text
    result = client.get(f"/api/v1/tasks/{task['task_id']}/result", headers=owner).json()
    assert {f["reason_code"] for f in result["findings"]} >= {
        "EFFECT_NOT_CONFIRMED",
        "EVENT_COVERAGE_LIMITED",
    }
    assert not any(f["classification"] == "Blocked" for f in result["findings"])
    assert app.state.store.evidence(binding.task_id, "coverage") == []
    value["effect_status"] = "observed"  # The captured negative return cannot establish an effect.
    assert (
        client.post(
            "/internal/v1/member2/events",
            json={"wire_format": "member2-normalized-1.0", "event": value},
            headers=sensor,
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {"process_exec": {}, "process_exit": {}},
        {"process_exec": {"process": {}, "parent": None}},
    ],
    ids=["null", "array", "ambiguous", "invalid-parent"],
)
def test_capture_shapes_fail_closed_without_fabricating_events(raw):
    from agentguard.sensors import MappingError

    with pytest.raises(MappingError):
        normalize_tetragon(raw, "protected-raw-reference", "lab-sensor", [])
