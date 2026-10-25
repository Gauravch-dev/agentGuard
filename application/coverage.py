"""Shared coverage checks for reconciliation and protected output release."""

from datetime import datetime, timedelta

from application.models import Binding, Coverage, Finding

REQUIRED_COVERAGE = {
    "host_sensor": {"process_exec", "file_access", "connection_attempt"},
    "network_sensor": {"egress_flow"},
}


def coverage_findings(
    binding: Binding, coverage: list[Coverage], start: datetime, end: datetime
) -> list[Finding]:
    findings = []
    for source, classes in REQUIRED_COVERAGE.items():
        for event_class in sorted(classes):
            windows = [
                c
                for c in coverage
                if c.task_id == binding.task_id
                and c.capsule_id == binding.capsule_id
                and c.source == source
                and event_class in c.event_classes
                and not c.simulated
            ]
            cursor = start
            for window in sorted(windows, key=lambda c: c.start):
                if (
                    window.status == "complete"
                    and not window.lost_events
                    and window.start <= cursor
                ):
                    cursor = max(cursor, window.end)
            conflicting = any(
                c.status != "complete" or c.lost_events
                for c in windows
                if c.start <= end and c.end > start
            )
            if not windows or cursor < end or conflicting:
                findings.append(
                    Finding(
                        classification="Unverified",
                        reason_code="MISSING_SENSOR_COVERAGE",
                        explanation=f"Incomplete {source}/{event_class} coverage for the execution interval.",
                        evidence_references=tuple(c.coverage_id for c in windows),
                    )
                )
    return findings


def release_coverage_ready(
    binding: Binding,
    coverage: list[Coverage],
    start: datetime,
    cutoff: datetime,
    checked_at: datetime,
) -> bool:
    if binding.simulated or cutoff < start or cutoff > checked_at:
        return False
    # Require independent coverage through the last broker action, plus freshness.
    # This does not certify activity after the release; TERE keeps tracking gaps.
    if coverage_findings(binding, coverage, start, cutoff):
        return False
    for source, classes in REQUIRED_COVERAGE.items():
        for event_class in classes:
            # Known recent loss/outage must hold output even if it starts after
            # the last completed broker action used as the coverage cutoff.
            if any(
                c.source == source
                and event_class in c.event_classes
                and c.task_id == binding.task_id
                and c.capsule_id == binding.capsule_id
                and not c.simulated
                and c.start <= checked_at
                and c.end > start
                and (c.status != "complete" or c.lost_events)
                for c in coverage
            ):
                return False
            if not any(
                c.source == source
                and event_class in c.event_classes
                and c.task_id == binding.task_id
                and c.capsule_id == binding.capsule_id
                and c.status == "complete"
                and not c.lost_events
                and not c.simulated
                and checked_at - timedelta(seconds=5) <= c.end <= checked_at
                for c in coverage
            ):
                return False
    return True
