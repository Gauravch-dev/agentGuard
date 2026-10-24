import json
import sqlite3
from datetime import timedelta

import pytest

from application.brokers import ChannelContext
from application.models import BrokerRequest, now
from application.synthetic import department_totals


def call(app, runtime, operation, payload=None, request_id="request-1"):
    return app.state.broker.handle(
        ChannelContext(runtime.binding.channel_id, runtime.binding.capsule_id),
        BrokerRequest(request_id=request_id, operation=operation, payload=payload or {}),
    )


@pytest.mark.parametrize(
    "operation,payload,reason",
    [
        ("data.get_raw_payroll", {}, "DENIED_OPERATION"),
        ("data.get_department_totals", {"sql": "SELECT * FROM payroll"}, "INVALID_DATA_PAYLOAD"),
        (
            "output.save_department_summary",
            {"employees": [{"salary": 82000}]},
            "OUTPUT_SCHEMA_VIOLATION",
        ),
        (
            "output.save_department_summary",
            department_totals().model_dump(mode="json")
            | {"destination": "https://example.invalid"},
            "OUTPUT_SCHEMA_VIOLATION",
        ),
        (
            "output.save_department_summary",
            {
                "departments": [
                    {"department": "Engineering", "total": "0"},
                    {"department": "Finance", "total": "140000"},
                    {"department": "Operations", "total": "120000"},
                ],
                "currency": "INR",
            },
            "TOTALS_MISMATCH",
        ),
    ],
)
def test_denied_operations_are_receipted(running, operation, payload, reason):
    (app, client, settings, runtime), task, headers = running
    response = call(app, runtime, operation, payload)
    assert response.receipt.verdict == "denied"
    assert response.receipt.effect_status == "blocked"
    assert response.receipt.reason == reason
    assert not app.state.store.evidence(task["task_id"], "report")


def test_aggregates_and_verified_report(running):
    (app, client, settings, runtime), task, headers = running
    aggregate = call(app, runtime, "data.get_department_totals").result
    assert "SYN-001" not in json.dumps(aggregate)
    report = call(app, runtime, "output.save_department_summary", aggregate, "release-1")
    assert report.receipt.effect_status == "completed"
    assert len(app.state.store.evidence(task["task_id"], "report")) == 1
    assert call(app, runtime, "output.save_department_summary", aggregate, "release-1") == report
    assert len(app.state.store.evidence(task["task_id"], "report")) == 1
    assert (
        call(app, runtime, "output.save_department_summary", aggregate, "release-2").receipt.reason
        == "OUTPUT_ALREADY_RELEASED"
    )
    with pytest.raises(ValueError):
        call(app, runtime, "data.get_raw_payroll", {}, "release-1")


def test_channel_cannot_choose_another_task(running):
    (app, client, settings, runtime), task, headers = running
    with pytest.raises(PermissionError):
        app.state.broker.handle(
            ChannelContext("forged", runtime.binding.capsule_id),
            BrokerRequest(request_id="x", operation="data.get_department_totals"),
        )
    response = call(app, runtime, "data.get_department_totals", {"task_id": "another-task"})
    assert response.receipt.verdict == "denied"


def test_no_model_fallback(running):
    (app, client, settings, runtime), task, headers = running
    response = call(
        app,
        runtime,
        "model.generate_report_draft",
        {
            "template_id": "finance_summary_v1",
            "aggregates": department_totals().model_dump(mode="json"),
        },
    )
    assert response.result is None
    assert response.receipt.effect_status == "unknown"
    assert response.receipt.reason == "MODEL_UNAVAILABLE"


def test_model_rejects_raw_or_wrong_aggregates(running):
    (app, client, settings, runtime), task, headers = running
    response = call(
        app,
        runtime,
        "model.generate_report_draft",
        {
            "template_id": "finance_summary_v1",
            "aggregates": {"employees": []},
            "url": "https://example.invalid",
        },
    )
    assert response.receipt.verdict == "denied"


def test_evidence_append_only_and_integrity(running):
    (app, client, settings, runtime), task, headers = running
    call(app, runtime, "data.get_raw_payroll")
    assert app.state.store.verify_chain()
    with pytest.raises(sqlite3.IntegrityError):
        app.state.store.db.execute("DELETE FROM evidence")
    with pytest.raises(sqlite3.IntegrityError):
        app.state.store.db.execute("UPDATE task_contracts SET body='{}'")
    # Simulate out-of-band corruption after bypassing database trigger.
    app.state.store.db.execute("DROP TRIGGER immutable_contract")
    app.state.store.db.execute("UPDATE task_contracts SET signature='tampered'")
    with pytest.raises(ValueError, match="INVALID_CONTRACT"):
        app.state.authority.get(task["task_id"], True)


def test_expired_contract_refuses_launch(stack):
    app, client, settings, runtime = stack
    contract = app.state.authority.create("synthetic-finance-owner")
    expired = contract.model_copy(update={"expires_at": now() - timedelta(seconds=1)}).model_dump(
        mode="json"
    )
    app.state.store.db.execute("DROP TRIGGER immutable_contract")
    app.state.store.db.execute(
        "UPDATE task_contracts SET body=?,signature=?",
        (json.dumps(expired), app.state.store.sign(expired)),
    )
    result = client.post(
        f"/api/v1/tasks/{contract.task_id}/launch",
        headers={"Authorization": f"Bearer {settings.owner_token}"},
    )
    assert result.status_code == 409
    assert runtime.calls == 0


def test_revision_requires_finished_task(running):
    (app, client, settings, runtime), task, headers = running
    assert (
        client.post(f"/api/v1/tasks/{task['task_id']}/revisions", headers=headers).status_code
        == 409
    )
    app.state.authority.transition(task["task_id"], "failed")
    revised = client.post(f"/api/v1/tasks/{task['task_id']}/revisions", headers=headers)
    assert revised.status_code == 201
    assert revised.json()["contract"]["contract_version"] == 2
    assert app.state.store.db.execute("SELECT count(*) FROM task_contracts").fetchone()[0] == 2
    with pytest.raises(PermissionError):
        call(app, runtime, "data.get_department_totals")


def test_corrupted_evidence_never_authorizes_broker_or_safe_result(running):
    (app, client, settings, runtime), task, headers = running
    app.state.store.db.execute("DROP TRIGGER immutable_evidence_update")
    app.state.store.db.execute("UPDATE evidence SET body='{}' WHERE kind='readiness'")
    assert not app.state.store.verify_chain()
    with pytest.raises(PermissionError):
        call(app, runtime, "data.get_department_totals")
    response = client.get(f"/api/v1/tasks/{task['task_id']}/result", headers=headers)
    assert response.status_code == 200
    result = response.json()
    assert result["integrity_verified"] is False
    assert result["reports"] == []
    assert [f["reason_code"] for f in result["findings"]] == ["INVALID_CONTRACT"]
