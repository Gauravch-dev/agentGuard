"""SIMULATIONS ONLY: owner views do not establish Linux acceptance evidence."""

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from application.brokers import ChannelContext
from application.posture import owner_posture
from application.rate_limit import RequestLimiter
from tests.integration.test_member2_bridge import upstream_process


def test_historical_revision_is_readable_but_never_authoritative(running):
    (app, client, settings, runtime), task, owner = running
    task_id = task["task_id"]
    old_binding = runtime.binding
    url = f"/api/v1/tasks/{task_id}"
    assert (
        client.post(url + "/notes", json={"text": "Reviewed first run"}, headers=owner).status_code
        == 201
    )
    app.state.authority.transition(task_id, "failed")
    assert client.post(url + "/revisions", headers=owner).status_code == 201
    assert client.post(url + "/launch", headers=owner).status_code == 200
    historical = client.get(url + "?version=1", headers=owner).json()
    assert historical["contract"]["contract_version"] == 1
    assert historical["current_version"] == 2
    assert historical["is_current"] is False
    assert historical["binding"]["capsule_id"] == old_binding.capsule_id
    assert client.get(url + "/notes?version=2", headers=owner).json() == []
    assert (
        client.get(url + "/notes?version=1", headers=owner).json()[0]["body"]["text"]
        == "Reviewed first run"
    )
    assert [r["version"] for r in client.get(url + "/revisions", headers=owner).json()] == [2, 1]
    assert (
        client.get(url + "/result?version=1", headers=owner).json()["business_outcome"] == "failed"
    )
    with pytest.raises(ValueError, match="inactive"):
        app.state.authority.get(task_id, require_active=True, version=1)
    with pytest.raises(PermissionError):
        app.state.broker.resolve(ChannelContext(old_binding.channel_id, old_binding.capsule_id))


@pytest.mark.parametrize("path", ["", "/result", "/posture", "/notes", "/events"])
def test_revision_queries_are_validated(running, path):
    (app, client, settings, runtime), task, owner = running
    url = f"/api/v1/tasks/{task['task_id']}{path}"
    for value in ("0", "invalid"):
        assert client.get(url, params={"version": value}, headers=owner).status_code == 422
    assert client.get(url, params={"version": 999}, headers=owner).status_code == 404


@pytest.mark.parametrize("path", ["/posture", "/revisions", "/notes"])
def test_owner_views_reject_runtime_and_sensor_credentials(running, path):
    (app, client, settings, runtime), task, owner = running
    for token in (settings.runtime_token, settings.sensors["lab-sensor"].token):
        response = client.get(
            f"/api/v1/tasks/{task['task_id']}{path}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403


def test_posture_sanitizes_sources_and_preserves_unknown_loss(running):
    (app, client, settings, runtime), task, owner = running
    binding = runtime.binding.model_copy(update={"cgroup_id": "cg-42"})

    class Observer:
        def status(self, capsule):
            return {
                "capsule_id": capsule,
                "cgroup_inode": 42,
                "protected_execution_ready": True,
                "private_path": "/private/credentials",
                "reasons": ["SOURCE_CLOCK_SEMANTICS_UNVERIFIED", "/private/credentials"],
                "sources": {
                    "process": {
                        "alive": True,
                        "last_heartbeat": time.monotonic(),
                        "pending": 2,
                        "gaps": 0,
                        "lost": None,
                        "export_failures": -1,
                        "token": "private-sensor-secret",
                    }
                },
            }

    runtime.supervisor = Observer()
    posture = owner_posture(app.state.store, task["task_id"], 1, binding, runtime, current=True)
    assert posture["protected_execution_ready"] is False
    assert posture["observer"]["connected"] is True
    source = posture["observer"]["sources"]["process"]
    assert source["fresh"] is True
    assert source["lost"] is None
    assert source["export_failures"] is None
    assert posture["observer"]["reasons"] == ["SOURCE_CLOCK_SEMANTICS_UNVERIFIED"]
    assert "private" not in str(posture)
    historical = owner_posture(app.state.store, task["task_id"], 1, binding, runtime, current=False)
    assert historical["observer"]["connected"] is False
    mismatched = owner_posture(
        app.state.store, task["task_id"], 1, runtime.binding, runtime, current=True
    )
    assert mismatched["observer"]["reasons"] == ["OBSERVER_STATUS_UNAVAILABLE"]


def test_evidence_pages_do_not_overlap(running):
    (app, client, settings, runtime), task, owner = running
    url = f"/api/v1/tasks/{task['task_id']}/events"
    latest = client.get(url, params={"version": 1, "limit": 3}, headers=owner).json()
    earlier = client.get(
        url, params={"version": 1, "limit": 3, "before": latest[0]["sequence"]}, headers=owner
    ).json()
    assert len(latest) == 3
    assert not {r["sequence"] for r in latest} & {r["sequence"] for r in earlier}
    assert client.get(url, params={"limit": 501}, headers=owner).status_code == 422


def test_limiter_bounds_memory_and_reclaims_idle_windows():
    limiter = RequestLimiter(capacity=2)
    assert limiter.allow("a", 1, 0)
    assert not limiter.allow("a", 1, 1)
    assert limiter.allow("b", 1, 1)
    assert not limiter.allow("c", 1, 2)
    assert len(limiter.windows) == 2
    assert limiter.allow("c", 1, 61)
    assert len(limiter.windows) == 1


def test_public_quota_cannot_starve_authenticated_owner(stack):
    app, client, settings, runtime = stack
    stamp = time.monotonic()
    for _ in range(600):
        assert app.state.request_limiter.allow("testclient", 600, stamp)
    assert client.get("/api/v1/health").status_code == 429
    response = client.get(
        "/api/v1/tasks", headers={"Authorization": f"Bearer {settings.owner_token}"}
    )
    assert response.status_code == 200


def test_concurrent_revision_requests_create_only_one_successor(running):
    (app, client, settings, runtime), task, owner = running
    task_id = task["task_id"]
    app.state.authority.transition(task_id, "failed")

    def revise(_):
        try:
            return app.state.authority.revise(task_id, "owner").contract_version
        except ValueError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(revise, range(2)))
    assert outcomes.count(2) == 1
    assert outcomes.count("refused") == 1


def test_late_ingestion_validates_historical_signature(running):
    (app, client, settings, runtime), task, owner = running
    task_id = task["task_id"]
    event = upstream_process(runtime.binding)
    app.state.authority.transition(task_id, "failed")
    assert client.post(f"/api/v1/tasks/{task_id}/revisions", headers=owner).status_code == 201
    # TEST ONLY: simulate privileged corruption by removing the immutable guard.
    app.state.store.db.execute("DROP TRIGGER immutable_contract")
    app.state.store.db.execute(
        "UPDATE task_contracts SET signature=? WHERE task_id=? AND version=1", ("invalid", task_id)
    )
    response = client.post(
        "/internal/v1/member2/events",
        json={"wire_format": "member2-normalized-1.0", "event": event},
        headers={"Authorization": f"Bearer {settings.sensors['lab-sensor'].token}"},
    )
    assert response.status_code == 409
    assert app.state.store.evidence(task_id, "event") == []
    assert client.get(f"/api/v1/tasks/{task_id}", headers=owner).status_code == 200
    result = client.get(f"/api/v1/tasks/{task_id}/result?version=1", headers=owner).json()
    assert result["integrity_verified"] is False
