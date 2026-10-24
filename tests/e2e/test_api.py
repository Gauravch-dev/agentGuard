from uuid import uuid4

from application.models import ProcessIdentity, SecurityEvent, now


def test_auth_roles_do_not_cross(stack):
    app, client, settings, runtime = stack
    assert client.get("/api/v1/tasks").status_code == 403
    assert (
        client.post(
            "/api/v1/tasks", json={}, headers={"Authorization": f"Bearer {settings.runtime_token}"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/internal/v1/events",
            json={},
            headers={"Authorization": f"Bearer {settings.owner_token}"},
        ).status_code
        == 403
    )
    assert client.get("/api/v1/health").json()["live_isolation_verified"] is False


def test_caller_cannot_expand_template(stack):
    app, client, settings, runtime = stack
    headers = {"Authorization": f"Bearer {settings.owner_token}"}
    response = client.post(
        "/api/v1/tasks",
        json={
            "direct_internet_allowed": True,
            "approved_by": "self",
            "allowed_operations": ["anything"],
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert "anything" not in response.text


def test_real_runtime_missing_fails_closed(tmp_path):
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
        task = client.post("/api/v1/tasks", json={}, headers=headers).json()["contract"]
        assert (
            client.post(f"/api/v1/tasks/{task['task_id']}/launch", headers=headers).status_code
            == 503
        )
        result = client.get(f"/api/v1/tasks/{task['task_id']}/result", headers=headers).json()
        assert result["business_outcome"] == "failed"
        assert all(f["classification"] == "Unverified" for f in result["findings"])
    app.state.store.db.close()


def test_sensor_source_auth_dedup_and_receipt_time(running):
    (app, client, settings, runtime), task, headers = running
    binding = runtime.binding
    item = SecurityEvent(
        event_id=uuid4().hex,
        task_id=task["task_id"],
        contract_version=1,
        capsule_id=binding.capsule_id,
        host_id=binding.host_id,
        source="host_sensor",
        event_type="process_exec",
        observed_at=now(),
        process_identity=ProcessIdentity(
            pid=123, start_time=binding.process_start, cgroup_id=binding.cgroup_id
        ),
        coverage_status="complete",
    )
    auth = {"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"}
    assert (
        client.post(
            "/internal/v1/events", json=item.model_dump(mode="json"), headers=headers
        ).status_code
        == 403
    )
    assert (
        client.post("/internal/v1/events", json=item.model_dump(mode="json"), headers=auth).json()[
            "duplicate"
        ]
        is False
    )
    assert (
        client.post("/internal/v1/events", json=item.model_dump(mode="json"), headers=auth).json()[
            "duplicate"
        ]
        is True
    )
    altered = item.model_copy(update={"resource_or_destination": "different"})
    assert (
        client.post(
            "/internal/v1/events", json=altered.model_dump(mode="json"), headers=auth
        ).status_code
        == 409
    )
    forged = item.model_copy(update={"source": "trusted_broker"})
    assert (
        client.post(
            "/internal/v1/events", json=forged.model_dump(mode="json"), headers=auth
        ).status_code
        == 403
    )
    events = app.state.store.evidence(task["task_id"], "event")
    assert len(events) == 1
    assert events[0]["body"]["received_at"]
    assert events[0]["body"]["event"]["observed_at"] == item.model_dump(mode="json")["observed_at"]
    result = client.get(f"/api/v1/tasks/{task['task_id']}/result", headers=headers).json()
    assert any(f["reason_code"] == "CONFLICTING_DUPLICATE" for f in result["findings"])


def test_body_limit_and_host_origin_rejection(stack):
    app, client, settings, runtime = stack
    assert client.post("/api/v1/tasks", content="x" * 33000).status_code == 413
    assert client.get("/api/v1/health", headers={"Host": "attacker.invalid"}).status_code == 400
    assert (
        client.get("/api/v1/health", headers={"Origin": "https://attacker.invalid"}).status_code
        == 403
    )


def test_termination_request_not_proof(running):
    (app, client, settings, runtime), task, headers = running
    response = client.post(f"/api/v1/tasks/{task['task_id']}/terminate", headers=headers)
    assert response.status_code == 409
    assert app.state.authority.record(task["task_id"])["state"] == "running"
    runtime.exit = True
    runtime.exit_state = "interrupted"
    assert (
        client.post(f"/api/v1/tasks/{task['task_id']}/terminate", headers=headers).status_code
        == 200
    )
