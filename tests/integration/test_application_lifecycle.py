"""SIMULATIONS ONLY: controller/socket/model doubles exercise application policy.

None of these records establish a real Linux, model or sensor acceptance result.
The real adapter is used with explicit doubles at its host integration boundaries.
"""

import copy
import secrets
import threading
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from application.api import create_app
from application.brokers import ChannelContext
from application.config import SensorIdentity, Settings
from application.models import BrokerRequest, Coverage, ToolChoice, now
from application.staged_runtime import StagedRuntimeAdapter
from application.synthetic import department_totals
from tests.integration.test_member2_bridge import ProbeOnlyLab


class FixtureController:
    """No Docker/processes: fixture records deliberately resemble owned records."""

    image_id = "sha256:" + "a" * 64

    def __init__(self):
        self.lab = ProbeOnlyLab()
        self.values = {}
        self.admission_check = None
        self.fail_terminate = False
        self.fail_admit = False
        self.in_admission = False
        self.recovered = False

    def prepare(self, contract):
        capsule = "capsule-" + uuid4().hex
        value = {
            "capsule_id": capsule,
            "task_id": contract["task_id"],
            "contract_version": contract["contract_version"],
            "state": "staged",
            "runtime_running": True,
            "admitted": False,
            "requested_stop": False,
            "descendants_exited": False,
            "channel_revoked": False,
            "exit_code": None,
            "channel_directory": "/fixture-not-a-real-socket/" + capsule,
            "identity": {
                "cgroup_inode": 991,
                "cgroup": "/fixture",
                "start_ticks": "15",
                "process_start_observed_at": now().isoformat(),
            },
        }
        self.values[capsule] = value
        return copy.deepcopy(value)

    def inspect(self, capsule):
        assert not self.in_admission, "Recursive inspection would deadlock the real record lock"
        return copy.deepcopy(self.values[capsule])

    def admit(self, capsule):
        self.in_admission = True
        try:
            if self.fail_admit or not self.admission_check(self.values[capsule]):
                raise RuntimeError("Fixture admission refused")
            self.values[capsule]["admitted"] = True
        finally:
            self.in_admission = False

    def finish(self, capsule, code=0):
        self.values[capsule].update(
            state="contained",
            runtime_running=False,
            descendants_exited=True,
            channel_revoked=True,
            contained_at=now().isoformat(),
            exit_code=code,
        )

    def terminate(self, capsule):
        if self.fail_terminate:
            raise OSError("Fixture Docker outage")
        self.values[capsule]["requested_stop"] = True
        self.finish(capsule, 137)

    def recover(self):
        self.recovered = True


class FixtureSockets:
    def __init__(self):
        self.opened, self.closed = [], []
        self.fail_open = False

    def open(self, value, binding, broker):
        if self.fail_open:
            raise OSError("Fixture socket setup failed")
        self.opened.append(binding.capsule_id)

    def close(self, capsule):
        self.closed.append(capsule)

    def shutdown(self):
        pass


class FixtureModel:
    def choose(self, request):
        return ToolChoice(
            operation="output.save_department_summary",
            payload=request.aggregates.model_dump(mode="json"),
        )


@pytest.fixture
def staged(tmp_path, monkeypatch):
    # A deterministic fixture clock avoids depending on Windows timer resolution.
    point = now() - timedelta(seconds=1)

    def tick():
        nonlocal point
        point += timedelta(milliseconds=1)
        return point

    for module in ("api", "authority", "brokers", "models", "store", "lifecycle", "staged_runtime"):
        monkeypatch.setattr(f"application.{module}.now", tick)
    monkeypatch.setattr(__name__ + ".now", tick)
    settings = Settings(
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        database=tmp_path / "lifecycle.sqlite3",
        local_model_enabled=True,
        approved_model_digest="a" * 64,
        sensors={
            "fixture-sensor": SensorIdentity(
                secrets.token_urlsafe(32), "fixture-host", ("host_sensor", "network_sensor")
            )
        },
    )
    controller, sockets = FixtureController(), FixtureSockets()
    runtime = StagedRuntimeAdapter(
        controller, "fixture-host", sockets=sockets, admission_review=lambda value: True
    )  # TEST ONLY
    app = create_app(settings, runtime)
    app.state.broker.model = FixtureModel()
    with TestClient(app) as client:
        owner = {"Authorization": f"Bearer {settings.owner_token}"}
        task = client.post("/api/v1/tasks", json={}, headers=owner).json()["contract"]["task_id"]
        yield app, client, settings, runtime, controller, owner, task
    app.state.store.db.close()


def prepare(stack):
    app, client, settings, runtime, controller, owner, task = stack
    response = client.post(f"/api/v1/tasks/{task}/launch", headers=owner)
    assert response.status_code == 200, response.text
    return app.state.lifecycle.binding(task)


def cover(stack, binding, *, end=None, lost=0):
    app, client, settings, runtime, controller, owner, task = stack
    for source, classes in (
        ("host_sensor", ("process_exec", "file_access", "connection_attempt")),
        ("network_sensor", ("egress_flow",)),
    ):
        window = Coverage(
            coverage_id=uuid4().hex,
            task_id=task,
            capsule_id=binding.capsule_id,
            sensor_id="fixture-sensor",
            source=source,
            event_classes=classes,
            start=binding.process_start,
            end=end or now(),
            status="complete",
            lost_events=lost,
        )
        response = client.post(
            "/internal/v1/coverage",
            json=window.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {settings.sensors['fixture-sensor'].token}"},
        )
        assert response.status_code == 200, response.text


def admit(stack, binding):
    app, client, settings, runtime, controller, owner, task = stack
    cover(stack, binding)
    response = client.post(f"/api/v1/tasks/{task}/admit", headers=owner)
    assert response.json()["state"] == "running", response.text


def channel(binding):
    return ChannelContext(binding.channel_id, binding.capsule_id)


def output(app, binding):
    return app.state.broker.handle(
        channel(binding),
        BrokerRequest(
            request_id=uuid4().hex,
            operation="output.save_department_summary",
            payload=department_totals().model_dump(mode="json"),
        ),
    )


def test_staging_registers_binding_but_does_not_authorize_agent(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    assert runtime.sockets.opened == [binding.capsule_id]
    assert not controller.values[binding.capsule_id]["admitted"]
    with pytest.raises(PermissionError):
        app.state.broker.resolve(channel(binding))
    status = client.get(f"/api/v1/tasks/{task}", headers=owner).json()["execution"]
    assert status["phase"] == "waiting_for_admission"
    assert "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE" in status["reasons"]
    assert (
        client.post(f"/api/v1/tasks/{task}/admit", headers=owner).json()["agent_admitted"] is False
    )
    assert (
        client.post(
            f"/api/v1/tasks/{task}/admit", json={"sensor_ready": True}, headers=owner
        ).status_code
        == 422
    )
    assert client.post(f"/api/v1/tasks/{task}/admit").status_code == 403


def test_default_review_stays_closed_even_with_fixture_full_coverage(staged):
    app, client, settings, runtime, controller, owner, task = staged
    runtime.admission_review = None
    binding = prepare(staged)
    cover(staged, binding)
    response = client.post(f"/api/v1/tasks/{task}/admit", headers=owner)
    assert response.json()["reasons"] == ["LIVE_PLATFORM_ADMISSION_REVIEW_PENDING"]
    assert not controller.values[binding.capsule_id]["admitted"]


def test_cancel_revokes_before_failed_cleanup_and_retry_verifies_exit(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    admit(staged, binding)
    controller.fail_terminate = True
    response = client.post(f"/api/v1/tasks/{task}/terminate", headers=owner)
    assert response.status_code == 409
    assert response.json()["channel_revoked"] is True
    with pytest.raises(PermissionError, match="durably revoked"):
        app.state.broker.resolve(channel(binding))
    assert (
        client.get(f"/api/v1/tasks/{task}", headers=owner).json()["execution"]["phase"]
        == "containment_unverified"
    )
    assessment = client.get(f"/api/v1/tasks/{task}/result", headers=owner).json()
    assert "CONTAINMENT_UNVERIFIED" in {f["reason_code"] for f in assessment["findings"]}
    app.state.authority.transition(task, "failed")
    assert client.post(f"/api/v1/tasks/{task}/revisions", headers=owner).status_code == 409
    controller.fail_terminate = False
    assert (
        client.post(f"/api/v1/tasks/{task}/terminate", headers=owner).json()["descendants_exited"]
        is True
    )
    assert client.post(f"/api/v1/tasks/{task}/revisions", headers=owner).status_code == 201
    assert app.state.lifecycle.binding(task) is None
    assert client.get(f"/api/v1/tasks/{task}", headers=owner).json()["readiness"] == []


def test_staged_task_can_be_cancelled_without_admission(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    response = client.post(f"/api/v1/tasks/{task}/terminate", headers=owner)
    assert response.json()["state"] == "interrupted"
    assert not controller.values[binding.capsule_id]["admitted"]


def test_socket_setup_failure_contains_and_records_failure(staged):
    app, client, settings, runtime, controller, owner, task = staged
    runtime.sockets.fail_open = True
    response = client.post(f"/api/v1/tasks/{task}/launch", headers=owner)
    assert response.status_code == 503
    binding = app.state.lifecycle.binding(task)
    assert controller.values[binding.capsule_id]["descendants_exited"]
    assert app.state.authority.record(task)["state"] == "failed"
    assert app.state.lifecycle.revoked(binding)


def test_admission_failure_revokes_and_contains(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    cover(staged, binding)
    controller.fail_admit = True
    with pytest.raises(RuntimeError, match="Fixture admission"):
        app.state.lifecycle.admit(task)
    assert app.state.authority.record(task)["state"] == "failed"
    assert app.state.lifecycle.revoked(binding)
    assert controller.values[binding.capsule_id]["descendants_exited"]


def test_coverage_loss_holds_output_and_contains_running_agent(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    admit(staged, binding)
    cover(staged, binding, lost=1)
    assert output(app, binding).receipt.reason == "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE"
    response = client.post(f"/api/v1/tasks/{task}/sync", headers=owner)
    assert response.json()["state"] == "interrupted"
    assert (
        app.state.store.evidence(task, "channel_revocation")[0]["body"]["reason"]
        == "LIVE_SENSOR_COVERAGE_LOST"
    )


def test_restart_revokes_old_binding_instead_of_resuming(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    admit(staged, binding)
    fresh_runtime = StagedRuntimeAdapter(controller, "fixture-host", sockets=FixtureSockets())
    restarted = create_app(settings, fresh_runtime)
    with TestClient(restarted) as second:
        assert controller.recovered
        assert second.get(f"/api/v1/tasks/{task}", headers=owner).json()["state"] == "interrupted"
        with pytest.raises(PermissionError):
            restarted.state.broker.resolve(channel(binding))
    restarted.state.store.db.close()


def test_expiry_revokes_and_contains_without_needing_owner_request(staged, monkeypatch):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    future = now() + timedelta(seconds=181)
    monkeypatch.setattr("application.lifecycle.now", lambda: future)
    app.state.lifecycle.refresh()
    assert app.state.authority.record(task)["state"] == "interrupted"
    assert app.state.lifecycle.revoked(binding)


def test_zero_exit_without_report_is_not_business_success(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    admit(staged, binding)
    controller.finish(binding.capsule_id)
    assert client.post(f"/api/v1/tasks/{task}/sync", headers=owner).json()["state"] == "failed"
    assert app.state.store.evidence(task, "report") == []


def test_final_coverage_can_arrive_late_without_reopening_channel(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    admit(staged, binding)
    cover(staged, binding)
    assert output(app, binding).receipt.effect_status == "completed"
    controller.finish(binding.capsule_id)
    response = client.post(f"/api/v1/tasks/{task}/sync", headers=owner)
    assert response.json()["phase"] == "awaiting_final_coverage"
    with pytest.raises(PermissionError, match="durably revoked"):
        app.state.broker.resolve(channel(binding))
    cover(staged, binding)
    response = client.post(f"/api/v1/tasks/{task}/sync", headers=owner)
    assert response.json()["state"] == "completed"
    assessment = client.get(f"/api/v1/tasks/{task}/result", headers=owner).json()
    assert "MISSING_SENSOR_COVERAGE" not in {f["reason_code"] for f in assessment["findings"]}
    assert app.state.store.verify_chain()


def test_late_coverage_timeout_never_promotes_business_success(staged, monkeypatch):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    admit(staged, binding)
    cover(staged, binding)
    assert output(app, binding).receipt.effect_status == "completed"
    controller.finish(binding.capsule_id)
    future = now() + timedelta(seconds=31)
    monkeypatch.setattr("application.lifecycle.now", lambda: future)
    assert app.state.lifecycle.sync(task)["state"] == "failed"


def test_runtime_completion_credential_cannot_force_success(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    response = client.post(
        f"/internal/v1/tasks/{task}/completion",
        json={"state": "completed", "capsule_id": binding.capsule_id, "descendants_exited": True},
        headers={"Authorization": f"Bearer {settings.runtime_token}"},
    )
    assert response.json()["state"] == "launch_requested"
    assert app.state.store.evidence(task, "report") == []


def test_background_monitor_contains_on_coverage_loss_without_owner_polling(staged, monkeypatch):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    admit(staged, binding)
    cover(staged, binding, lost=1)
    refreshed = threading.Event()
    refresh = app.state.lifecycle.refresh

    def observed_refresh():
        refresh()
        refreshed.set()

    monkeypatch.setattr(app.state.lifecycle, "refresh", observed_refresh)
    assert refreshed.wait(4), "The background lifecycle monitor did not run"
    assert app.state.authority.record(task)["state"] == "interrupted"
    assert controller.values[binding.capsule_id]["descendants_exited"]


def conflicting_coverage(stack, binding):
    app, client, settings, runtime, controller, owner, task = stack
    original = app.state.store.evidence(task, "coverage")[0]["body"]
    response = client.post(
        "/internal/v1/coverage",
        json=original | {"lost_events": 1},
        headers={"Authorization": f"Bearer {settings.sensors['fixture-sensor'].token}"},
    )
    assert response.status_code == 409


def test_conflicting_source_evidence_blocks_admission_despite_complete_coverage(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    cover(staged, binding)
    conflicting_coverage(staged, binding)
    cover(staged, binding)
    response = client.post(f"/api/v1/tasks/{task}/admit", headers=owner)
    assert response.json()["agent_admitted"] is False
    assert "SOURCE_EVIDENCE_CONFLICT" in response.json()["reasons"]
    assert not controller.values[binding.capsule_id]["admitted"]


def test_final_coverage_cannot_hide_a_recorded_source_conflict(staged):
    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    admit(staged, binding)
    cover(staged, binding)
    assert output(app, binding).receipt.effect_status == "completed"
    conflicting_coverage(staged, binding)
    controller.finish(binding.capsule_id)
    cover(staged, binding)
    assert app.state.lifecycle.sync(task)["state"] == "failed"
    result = client.get(f"/api/v1/tasks/{task}/result", headers=owner).json()
    assert "CONFLICTING_DUPLICATE" in {f["reason_code"] for f in result["findings"]}


def test_live_admission_reason_is_scoped_to_the_reviewed_capsule(staged, monkeypatch):
    from agentguard.admission_review import LiveAdmissionReview

    app, client, settings, runtime, controller, owner, task = staged
    binding = prepare(staged)
    cover(staged, binding)
    review = LiveAdmissionReview(None, None)
    monkeypatch.setattr(
        review,
        "reasons",
        lambda value: [
            "CONTINUOUS_SENSOR_SUPERVISION_UNAVAILABLE",
            "not a safe reason: private path",
        ],
    )
    runtime.admission_review = review
    response = client.post(f"/api/v1/tasks/{task}/admit", headers=owner)
    assert response.json()["agent_admitted"] is False
    assert response.json()["reasons"] == [
        "LIVE_PLATFORM_ADMISSION_REVIEW_PENDING",
        "CONTINUOUS_SENSOR_SUPERVISION_UNAVAILABLE",
    ]
    assert not controller.values[binding.capsule_id]["admitted"]
