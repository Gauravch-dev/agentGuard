"""Transport simulations: retries/checkpoints are not live coverage evidence."""

import json
import os
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
