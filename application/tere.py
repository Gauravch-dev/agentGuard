"""Pure evidence-aware Task-Effect Reconciliation Engine; no model adjudication."""

from datetime import datetime, timedelta
from typing import Literal

from application.coverage import coverage_findings
from application.models import Binding, Coverage, EventEnvelope, Finding, Receipt, TaskContract


def reconcile(
    contract: TaskContract | None,
    binding: Binding | None,
    receipts: list[Receipt],
    events: list[EventEnvelope],
    coverage: list[Coverage],
    start: datetime,
    end: datetime,
    integrity_valid: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []

    def add(
        kind: Literal["Aligned", "Blocked", "Unexplained", "Unverified"],
        reason: str,
        explanation: str,
        refs: tuple[str, ...] = (),
    ) -> None:
        findings.append(
            Finding(
                classification=kind,
                reason_code=reason,
                explanation=explanation,
                evidence_references=refs,
            )
        )

    if not integrity_valid or contract is None:
        add("Unverified", "INVALID_CONTRACT", "Contract/evidence integrity verification failed.")
        return findings
    if (
        binding is None
        or binding.task_id != contract.task_id
        or binding.contract_version != contract.contract_version
    ):
        add(
            "Unverified",
            "MISSING_TRUSTED_BINDING",
            "No trusted mapping for this contract execution.",
        )
        return findings
    if binding.simulated:
        add(
            "Unverified",
            "SIMULATED_RUNTIME",
            "Test simulation; no Linux isolation or sensor claim.",
        )
    if contract.expires_at < end:
        add(
            "Unverified", "CONTRACT_EXPIRED_DURING_RUN", "Execution extends beyond approved expiry."
        )
    if end < start:
        add("Unverified", "INVALID_EXECUTION_WINDOW", "Execution end precedes start.")
        return findings
    findings.extend(coverage_findings(binding, coverage, start, end))
    matching: dict[str, Receipt] = {}
    for receipt in receipts:
        if receipt.task_id != contract.task_id or receipt.capsule_id != binding.capsule_id:
            add(
                "Unverified",
                "RECEIPT_BINDING_MISMATCH",
                "Broker receipt does not match execution.",
                (receipt.evidence_reference,),
            )
            continue
        if not start <= receipt.observed_at <= end:
            add(
                "Unverified",
                "OUTSIDE_EXECUTION_WINDOW",
                "Broker receipt outside execution window.",
                (receipt.evidence_reference,),
            )
            continue
        matching[receipt.correlation_id] = receipt
        if receipt.verdict == "denied" and receipt.effect_status == "blocked":
            add(
                "Blocked",
                receipt.reason,
                "Trusted broker denied the operation. Independent host attempt evidence may be unavailable; this is not a completed leak.",
                (receipt.evidence_reference,),
            )
        elif (
            receipt.verdict == "allowed"
            and receipt.effect_status == "completed"
            and receipt.operation in contract.allowed_operations
        ):
            add(
                "Aligned",
                "BROKER_EFFECT_CONFIRMED",
                "Permitted broker operation completed. Coverage findings describe independent observation limits.",
                (receipt.evidence_reference,),
            )
        else:
            add(
                "Unverified",
                "BROKER_EFFECT_UNCONFIRMED",
                "Broker did not confirm an authorized completed effect.",
                (receipt.evidence_reference,),
            )
    seen: dict[tuple[str, str], EventEnvelope] = {}
    for envelope in events:
        event = envelope.event
        identity = (envelope.sensor_id, event.event_id)
        if identity in seen:
            if seen[identity].event != event:
                add(
                    "Unverified",
                    "CONFLICTING_DUPLICATE",
                    "Same source/event identity has conflicting records.",
                )
            continue
        seen[identity] = envelope
        refs = (event.evidence_reference or event.event_id,)
        if envelope.simulated:
            add(
                "Unverified",
                "SIMULATED_EVENT",
                "Simulated test observation, not live host evidence.",
                refs,
            )
            continue
        mapped = (
            event.task_id == contract.task_id
            and event.contract_version == contract.contract_version
            and event.capsule_id == binding.capsule_id
            and event.host_id == binding.host_id
        )
        process = event.process_identity
        if event.source in {"host_sensor", "network_sensor"}:
            mapped = (
                mapped
                and process is not None
                and process.cgroup_id == binding.cgroup_id
                and process.start_time is not None
                and binding.process_start <= process.start_time <= event.observed_at
            )
        if not mapped:
            add(
                "Unverified",
                "ATTRIBUTION_FAILURE",
                "Cannot attribute event by trusted cgroup/start identity; PID or timing alone is insufficient.",
                refs,
            )
            continue
        if (
            not start <= event.observed_at <= end
            or event.observed_at > envelope.received_at + timedelta(seconds=5)
        ):
            add(
                "Unverified",
                "CLOCK_OR_WINDOW_MISMATCH",
                "Observation outside execution window or ahead of receipt clock.",
                refs,
            )
            continue
        if event.coverage_status != "complete":
            add(
                "Unverified",
                "EVENT_COVERAGE_LIMITED",
                "Observation has incomplete or unknown coverage.",
                refs,
            )
        if (
            event.policy_verdict == "denied"
            and event.effect_status == "blocked"
            and event.source == "policy_engine"
        ):
            add(
                "Blocked",
                "DENIED_OPERATION",
                "Trusted enforcement reports a blocked attempt; no completed external transfer is established.",
                refs,
            )
            continue
        if event.event_type in {"file_access", "egress_flow", "connection_attempt"}:
            related_receipt = matching.get(event.correlation_id or "")
            explained = (
                event.event_type != "egress_flow"
                and related_receipt is not None
                and related_receipt.verdict == "allowed"
                and related_receipt.effect_status == "completed"
                and event.operation == related_receipt.operation
                and event.resource_or_destination == contract.approved_output_destination
            )
            if event.effect_status in {"observed", "completed"} and not explained:
                add(
                    "Unexplained",
                    "UNMATCHED_HOST_EFFECT",
                    "Attributable host/network effect lacks an approved explanation. Flow contents are unknown.",
                    refs,
                )
            elif event.effect_status in {"attempted", "unknown", "blocked"}:
                add(
                    "Unverified",
                    "EFFECT_NOT_CONFIRMED",
                    "Attempt observation alone establishes neither completed effect nor trusted prevention.",
                    refs,
                )
    if not receipts and not events:
        add(
            "Unverified",
            "NO_EVIDENCE",
            "No observations; absence of evidence does not establish safety.",
        )
    return findings
