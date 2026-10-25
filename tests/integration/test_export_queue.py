"""Transport simulations: retries/checkpoints are not live coverage evidence."""

import json
import os
import sqlite3
import sys

import httpx
import pytest

from agentguard.export_queue import ExportQueue

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux private collector state required"
)


def normalize(line, reference):
    return {"wire_format": "test-only", "event": json.loads(line), "reference": reference}


def private_capture(tmp_path, content):
    path = tmp_path / "capture.jsonl"
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def test_reconnect_retains_exact_frame_and_restart_resumes_checkpoint(tmp_path):
    path = private_capture(tmp_path, b'{"event_id":"one"}\n{"event_id":"two"}\n')
    queue = ExportQueue(tmp_path / "queue", "sensor-one")
    assert queue.tail(path, normalize) == 2
    seen = []

    def outage(request):
        seen.append(request.content)
        return httpx.Response(503)

    with httpx.Client(transport=httpx.MockTransport(outage)) as client:
        assert queue.drain("x" * 32, client=client) == 0
    assert queue.status()["pending"] == 2
    queue.close()
    queue = ExportQueue(tmp_path / "queue", "sensor-one")
    assert queue.tail(path, normalize) == 0

    def recovered(request):
        seen.append(request.content)
        return httpx.Response(200, json={"accepted": True, "duplicate": True})

    with httpx.Client(transport=httpx.MockTransport(recovered)) as client:
        assert queue.drain("x" * 32, client=client) == 2
    assert seen[0] == seen[1]
    assert queue.status() == {
        "pending": 0,
        "delivered": 2,
        "gaps": 2,
        "export_failures": 1,
        "coverage_promoted": False,
    }
    queue.close()


def test_partial_tail_rotation_and_normalization_loss_remain_gaps(tmp_path):
    path = private_capture(tmp_path, b'{"event_id":"one"}')
    queue = ExportQueue(tmp_path / "queue", "sensor-one")
    assert queue.tail(path, normalize) == 0
    with path.open("ab") as stream:
        stream.write(b"\ninvalid\n")
    assert queue.tail(path, normalize) == 1
    before = queue.status()["gaps"]
    replacement = tmp_path / "new"
    replacement.write_bytes(b'{"event_id":"rotated"}\n')
    replacement.chmod(0o600)
    os.replace(replacement, path)
    assert queue.tail(path, normalize) == 1
    assert queue.status()["gaps"] == before + 1
    assert queue.status()["coverage_promoted"] is False
    with pytest.raises(PermissionError):
        ExportQueue(tmp_path / "queue", "another-sensor")
    queue.close()


def test_missing_ack_is_not_delivery_and_checkpoint_rewrite_is_detected(tmp_path):
    path = private_capture(tmp_path, b'{"event_id":"one"}\n')
    queue = ExportQueue(tmp_path / "queue", "sensor-one")
    assert queue.tail(path, normalize) == 1
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    ) as client:
        assert queue.drain("x" * 32, client=client) == 0
    path.write_bytes(b'{"event_id":"two"}\n')
    assert queue.tail(path, normalize) == 1
    reasons = [r[0] for r in queue.db.execute("SELECT reason FROM gaps")]
    assert "CHECKPOINT_CONTENT_CHANGED" in reasons
    assert queue.status()["pending"] == 2
    queue.close()


def test_second_collector_cannot_share_the_same_checkpoint(tmp_path):
    queue = ExportQueue(tmp_path / "queue", "sensor-one")
    try:
        with pytest.raises(PermissionError):
            ExportQueue(tmp_path / "queue", "sensor-one")
    finally:
        queue.close()
        queue.close()  # Cleanup after a failed restart must not close a reused FD.


def test_packet_and_coverage_routes_are_durable_and_cannot_redirect(tmp_path):
    queue = ExportQueue(tmp_path / "queue", "packet-source")
    with queue.db:
        queue.enqueue({"event_id": "actual-source-shape"}, endpoint="events")
        queue.enqueue({"coverage_id": "partial-test-window"}, endpoint="coverage")
    queue.close()
    queue = ExportQueue(tmp_path / "queue", "packet-source")
    paths = []

    def accept(request):
        paths.append(str(request.url))
        return httpx.Response(200, json={"accepted": True})

    with httpx.Client(transport=httpx.MockTransport(accept)) as client:
        assert queue.drain("x" * 32, client=client) == 2
    assert paths == [
        "http://127.0.0.1:8000/internal/v1/events",
        "http://127.0.0.1:8000/internal/v1/coverage",
    ]
    with pytest.raises(ValueError):
        queue.enqueue({}, endpoint="https://example.invalid")
    queue.close()


def test_existing_queue_schema_migrates_without_discarding_undelivered_evidence(tmp_path):
    root = tmp_path / "queue"
    root.mkdir(mode=0o700)
    path = root / "export.sqlite3"
    with sqlite3.connect(path) as database:
        database.execute(
            "CREATE TABLE frames (seq INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)"
        )
        database.execute("INSERT INTO frames(event_key,payload) VALUES ('legacy-key','{}')")
    path.chmod(0o600)
    queue = ExportQueue(root, "process-source")
    assert queue.db.execute("SELECT endpoint FROM frames").fetchone()[0] == "member2"
    assert queue.status()["pending"] == 1
    queue.close()


def test_corrupted_persisted_route_cannot_send_sensor_credentials_elsewhere(tmp_path):
    queue = ExportQueue(tmp_path / "queue", "test-source")
    with queue.db:
        queue.db.execute(
            "INSERT INTO frames(event_key,payload,endpoint) VALUES ('corrupt','{}','https://example.invalid')"
        )
    requests = []
    with httpx.Client(transport=httpx.MockTransport(lambda r: requests.append(r))) as client:
        assert queue.drain("x" * 32, client=client) == 0
    assert requests == [] and queue.status()["pending"] == 1
    queue.close()


def test_queue_migration_cannot_run_without_the_exclusive_collector_lease(tmp_path):
    import fcntl

    root = tmp_path / "queue"
    root.mkdir(mode=0o700)
    path = root / "export.sqlite3"
    with sqlite3.connect(path) as database:
        database.execute(
            "CREATE TABLE frames (seq INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)"
        )
    path.chmod(0o600)
    with (root / "collector.lock").open("w") as lease:
        fcntl.flock(lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(PermissionError):
            ExportQueue(root, "test-source")
        with sqlite3.connect(path) as database:
            assert "endpoint" not in {
                row[1] for row in database.execute("PRAGMA table_info(frames)")
            }


def test_delivery_budget_yields_without_losing_or_acknowledging_pending_frames(
    tmp_path, monkeypatch
):
    from agentguard import export_queue

    queue = ExportQueue(tmp_path / "queue", "test-source")
    with queue.db:
        queue.enqueue({"event_id": "first"})
        queue.enqueue({"event_id": "second"})
    ticks = iter([0.0, 0.0, 1.0])
    from types import SimpleNamespace

    monkeypatch.setattr(export_queue, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    with httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"accepted": True}))
    ) as client:
        assert queue.drain("x" * 32, client=client, max_seconds=0.5) == 1
    assert queue.status()["pending"] == 1
    assert queue.status()["export_failures"] == 0
    queue.close()


@pytest.mark.parametrize("budget", [0, -1, float("nan"), float("inf"), True, 10])
def test_invalid_delivery_time_budgets_are_refused(tmp_path, budget):
    queue = ExportQueue(tmp_path / "queue", "test-source")
    try:
        with pytest.raises(ValueError):
            queue.drain("x" * 32, max_seconds=budget)
    finally:
        queue.close()
