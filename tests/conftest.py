"""SIMULATIONS ONLY: test fixtures never become live host evidence."""

import secrets
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from application.api import create_app
from application.config import SensorIdentity, Settings
from application.models import Binding, RuntimeResult, now
from application.runtime_adapter import REQUIRED_CONTROLS


class TestRuntime:
    """Trusted adapter double, not a real Linux security control."""

    __test__ = False

    def __init__(self):
        self.binding = None
        self.exit = False
        self.exit_state = "completed"
        self.calls = 0

    def launch(self, contract_ref):
        self.calls += 1
        self.binding = Binding(
            task_id=contract_ref.task_id,
            contract_version=contract_ref.contract_version,
            capsule_id=f"fixture-{uuid4().hex}",
            host_id="lab-host",
            cgroup_id=f"fixture-cg-{uuid4().hex}",
            process_start=now() - timedelta(milliseconds=10),
            registered_at=now(),
            channel_id=uuid4().hex,
        )
        # Non-simulated flag tests the live gate; entire adapter exists only in tests.
        return RuntimeResult(
            state="running",
            readiness_passed=True,
            controls=tuple(REQUIRED_CONTROLS),
            reason="TEST DOUBLE",
            binding=self.binding,
        )

    def inspect(self, capsule_id):
        return RuntimeResult(
            state=self.exit_state if self.exit else "running",
            readiness_passed=True,
            reason="TEST DOUBLE",
            binding=self.binding,
            descendants_exited=self.exit,
        )

    def terminate(self, capsule_id):
        return self.inspect(capsule_id)

    def observe(self):
        return iter(())


@pytest.fixture
def stack(tmp_path):
    settings = Settings(
        owner_token=secrets.token_urlsafe(32),
        runtime_token=secrets.token_urlsafe(32),
        integrity_key=secrets.token_urlsafe(32),
        database=tmp_path / "evidence.sqlite3",
        sensors={
            "lab-sensor": SensorIdentity(
                secrets.token_urlsafe(32),
                "lab-host",
                ("host_sensor", "network_sensor", "policy_engine", "sensor_health"),
            )
        },
    )
    runtime = TestRuntime()
    app = create_app(settings, runtime)
    # TEST ONLY: deterministic business-flow checks do not claim independent sensor coverage.
    app.state.broker.coverage_check = lambda binding: True
    with TestClient(app) as client:
        yield app, client, settings, runtime
    app.state.store.db.close()


@pytest.fixture
def running(stack):
    app, client, settings, runtime = stack
    headers = {"Authorization": f"Bearer {settings.owner_token}"}
    task = client.post("/api/v1/tasks", json={}, headers=headers).json()["contract"]
    response = client.post(f"/api/v1/tasks/{task['task_id']}/launch", headers=headers)
    assert response.status_code == 200, response.text
    return stack, task, headers
