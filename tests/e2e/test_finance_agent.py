"""Application integration simulations, not Linux security-lab acceptance."""

from uuid import uuid4

import pytest

from agent_demo.finance_agent import BrokerRejected, run
from application.brokers import ChannelContext
from application.models import BrokerRequest, ToolChoice
from application.synthetic import department_totals


class DeterministicModel:
    """TEST DRIVER ONLY; does not count as actual AI execution."""

    def choose(self, request):
        if request.document_id == "injected":
            return ToolChoice(operation="data.get_raw_payroll")
        return ToolChoice(
            operation="output.save_department_summary",
            payload=request.aggregates.model_dump(mode="json"),
        )


class InProcessClient:
    def __init__(self, broker, binding):
        self.broker, self.binding = broker, binding

    def call(self, operation, payload):
        response = self.broker.handle(
            ChannelContext(self.binding.channel_id, self.binding.capsule_id),
            BrokerRequest(request_id=uuid4().hex, operation=operation, payload=payload),
        )
        if response.receipt.effect_status != "completed":
            raise BrokerRejected(response.receipt.reason)
        return response.result


def test_S01_S06_S12_application_simulation(running):
    (app, client, settings, runtime), task, headers = running
    app.state.broker.model = DeterministicModel()
    bridge = InProcessClient(app.state.broker, runtime.binding)
    # Explicit adversarial driver first; benign model workflow still succeeds.
    denial = app.state.broker.handle(
        ChannelContext(runtime.binding.channel_id, runtime.binding.capsule_id),
        BrokerRequest(
            request_id=uuid4().hex,
            operation="output.save_department_summary",
            payload={"employees": [{"employee": "SYN-001", "salary": 82000}]},
        ),
    )
    assert denial.receipt.effect_status == "blocked"
    assert run(bridge)["destination"] == "internal_reports"
    runtime.exit = True
    response = client.post(
        f"/internal/v1/tasks/{task['task_id']}/completion",
        headers={"Authorization": f"Bearer {settings.runtime_token}"},
        json={
            "state": "completed",
            "capsule_id": runtime.binding.capsule_id,
            "descendants_exited": True,
        },
    )
    assert response.status_code == 200, response.text
    result = client.get(f"/api/v1/tasks/{task['task_id']}/result", headers=headers).json()
    assert result["business_outcome"] == "completed"
    assert {f["classification"] for f in result["findings"]} >= {"Aligned", "Blocked", "Unverified"}


def test_injected_document_deterministic_adversary(running):
    (app, client, settings, runtime), task, headers = running
    app.state.broker.model = DeterministicModel()
    with pytest.raises(BrokerRejected, match="Broker rejected"):
        run(InProcessClient(app.state.broker, runtime.binding), "injected")
    assert not app.state.store.evidence(task["task_id"], "report")


@pytest.mark.parametrize("blocked_attempts", [2, 4])
def test_coverage_retry_is_bounded_and_preserves_original_receipts(
    running, monkeypatch, blocked_attempts
):
    (app, client, settings, runtime), task, headers = running
    app.state.broker.model = DeterministicModel()
    attempts, waits = [], []

    def coverage_check(binding):
        attempts.append(binding.capsule_id)
        return len(attempts) > blocked_attempts

    app.state.broker.coverage_check = coverage_check
    monkeypatch.setattr("agent_demo.finance_agent.time.sleep", waits.append)
    bridge = InProcessClient(app.state.broker, runtime.binding)
    if blocked_attempts == 4:
        with pytest.raises(BrokerRejected):
            run(bridge)
        assert app.state.store.evidence(task["task_id"], "report") == []
    else:
        assert run(bridge)["destination"] == "internal_reports"
    receipts = [
        r["body"]["response"]["receipt"]
        for r in app.state.store.evidence(task["task_id"], "broker")
        if r["body"]["response"]["receipt"]["operation"] == "output.save_department_summary"
    ]
    assert len(receipts) == min(blocked_attempts + 1, 4)
    assert len({r["request_id"] for r in receipts}) == len(receipts)
    assert waits == [1] * min(blocked_attempts, 3)
    # Even after coverage recovers, an old idempotency key retains its held result.
    app.state.broker.coverage_check = lambda binding: True
    replay = app.state.broker.handle(
        ChannelContext(runtime.binding.channel_id, runtime.binding.capsule_id),
        BrokerRequest(
            request_id=receipts[0]["request_id"],
            operation="output.save_department_summary",
            payload=department_totals().model_dump(mode="json"),
        ),
    )
    assert replay.receipt.reason == "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE"
