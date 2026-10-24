from datetime import timedelta
from uuid import uuid4

import pytest

from application.models import Coverage, EventEnvelope, ProcessIdentity, SecurityEvent, now
from application.synthetic import department_totals
from application.tere import reconcile
from tests.unit.test_brokers_authority import call

# Entire module uses generated observations, never actual Linux telemetry.


def inputs(running):
    (app, client, settings, runtime), task, headers = running
    contract = app.state.authority.get(task["task_id"])
    start = runtime.binding.registered_at
    return contract, runtime.binding, [], [], [], start, now() + timedelta(seconds=1)


def event(args, **updates):
    contract, binding, _, _, _, start, end = args
    fields = dict(
        event_id=uuid4().hex,
        task_id=contract.task_id,
        contract_version=1,
        capsule_id=binding.capsule_id,
        host_id=binding.host_id,
        source="network_sensor",
        event_type="egress_flow",
        observed_at=start + timedelta(milliseconds=1),
        process_identity=ProcessIdentity(
            pid=123, start_time=binding.process_start, cgroup_id=binding.cgroup_id
        ),
        operation="connect",
        resource_or_destination="https://example.invalid",
        effect_status="observed",
        coverage_status="complete",
    )
    fields.update(updates)
    return EventEnvelope(event=SecurityEvent(**fields), sensor_id="lab-sensor", received_at=end)


def codes(findings):
    return {f.reason_code for f in findings}


def test_no_events_is_not_safe(running):
    findings = reconcile(*inputs(running))
    assert "NO_EVIDENCE" in codes(findings)
    assert all(f.classification == "Unverified" for f in findings)


def test_attributable_unknown_flow_does_not_claim_contents(running):
    args = list(inputs(running))
    args[3] = [event(args)]
    findings = reconcile(*args)
    assert "UNMATCHED_HOST_EFFECT" in codes(findings)
    assert any(
        f.classification == "Unexplained" and "contents are unknown" in f.explanation
        for f in findings
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"capsule_id": "wrong"},
        {"host_id": "wrong"},
        {"process_identity": ProcessIdentity(pid=123, start_time=now(), cgroup_id="wrong")},
        {"process_identity": ProcessIdentity(pid=123)},
        {
            "process_identity": ProcessIdentity(
                pid=123, start_time=now() - timedelta(days=1), cgroup_id="wrong"
            )
        },
    ],
)
def test_pid_or_time_alone_never_attributes(running, updates):
    args = list(inputs(running))
    args[3] = [event(args, **updates)]
    findings = reconcile(*args)
    assert "ATTRIBUTION_FAILURE" in codes(findings)
    assert not any(f.classification == "Unexplained" for f in findings)


def test_skew_and_unknown_effect(running):
    args = list(inputs(running))
    args[3] = [event(args, observed_at=args[6] + timedelta(minutes=1))]
    assert "CLOCK_OR_WINDOW_MISMATCH" in codes(reconcile(*args))
    args[3] = [event(args, effect_status="attempted")]
    findings = reconcile(*args)
    assert "EFFECT_NOT_CONFIRMED" in codes(findings)
    assert not any(f.classification == "Blocked" for f in findings)


def test_blocked_and_aligned_can_coexist_with_missing_coverage(running):
    (app, client, settings, runtime), task, headers = running
    denied = call(app, runtime, "data.get_raw_payroll").receipt
    aligned = call(app, runtime, "data.get_department_totals", request_id="ok").receipt
    args = list(inputs(running))
    args[2] = [denied, aligned]
    args[5] = runtime.binding.process_start
    classifications = {f.classification for f in reconcile(*args)}
    assert classifications == {"Blocked", "Aligned", "Unverified"}


def test_complete_coverage_scoped_and_loss_overrides(running):
    args = list(inputs(running))
    contract, binding, _, _, _, start, end = args
    windows = []
    for source, classes in [
        ("host_sensor", ("process_exec", "file_access", "connection_attempt")),
        ("network_sensor", ("egress_flow",)),
    ]:
        windows.append(
            Coverage(
                coverage_id=uuid4().hex,
                task_id=contract.task_id,
                capsule_id=binding.capsule_id,
                sensor_id="lab-sensor",
                source=source,
                event_classes=classes,
                start=start,
                end=end,
                status="complete",
            )
        )
    args[4] = windows
    assert "MISSING_SENSOR_COVERAGE" not in codes(reconcile(*args))
    args[4] = [windows[0].model_copy(update={"lost_events": 1}), windows[1]]
    assert "MISSING_SENSOR_COVERAGE" in codes(reconcile(*args))


def test_duplicates_and_conflicts(running):
    args = list(inputs(running))
    one = event(args)
    args[3] = [one, one]
    assert len([f for f in reconcile(*args) if f.classification == "Unexplained"]) == 1
    args[3] = [
        one,
        one.model_copy(update={"event": one.event.model_copy(update={"effect_status": "unknown"})}),
    ]
    assert "CONFLICTING_DUPLICATE" in codes(reconcile(*args))


def test_simulated_sources_never_become_host_evidence(running):
    args = list(inputs(running))
    args[3] = [event(args).model_copy(update={"simulated": True})]
    findings = reconcile(*args)
    assert "SIMULATED_EVENT" in codes(findings)
    assert not any(f.classification == "Unexplained" for f in findings)


def test_network_effect_not_authorized_by_borrowed_broker_correlation(running):
    (app, client, settings, runtime), task, headers = running
    receipt = call(
        app,
        runtime,
        "output.save_department_summary",
        department_totals().model_dump(mode="json"),
    ).receipt
    args = list(inputs(running))
    args[2] = [receipt]
    args[3] = [
        event(
            args,
            correlation_id=receipt.correlation_id,
            operation=receipt.operation,
            resource_or_destination="internal_reports",
        )
    ]
    args[5] = runtime.binding.process_start
    assert "UNMATCHED_HOST_EFFECT" in codes(reconcile(*args))
