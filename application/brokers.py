"""Trusted broker, called only with a launcher/peer-resolved channel identity."""

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from uuid import uuid4

from pydantic import ValidationError

from application.authority import Authority
from application.model_provider import ModelProvider, ModelUnavailable
from application.models import (
    Binding,
    BrokerRequest,
    BrokerResponse,
    ModelRequest,
    Receipt,
    Report,
    now,
)
from application.store import Store, canonical
from application.synthetic import department_totals


@dataclass(frozen=True)
class ChannelContext:
    # Created by trusted peer resolver, never from request JSON.
    channel_id: str
    capsule_id: str


class Broker:
    def __init__(
        self,
        store: Store,
        authority: Authority,
        model: ModelProvider,
        coverage_check: Callable[[Binding], bool] | None = None,
    ):
        self.store, self.authority, self.model = store, authority, model
        self.coverage_check = coverage_check

    def resolve(self, channel: ChannelContext) -> Binding:
        if not self.store.verify_chain():
            raise PermissionError("Evidence integrity check failed")
        with self.store.lock:
            rows = self.store.db.execute(
                "SELECT body FROM evidence WHERE kind='binding'"
            ).fetchall()
        matches = [Binding.model_validate_json(row[0]) for row in rows]
        binding = next(
            (
                b
                for b in matches
                if hmac.compare_digest(b.channel_id, channel.channel_id)
                and b.capsule_id == channel.capsule_id
            ),
            None,
        )
        if binding is None:
            raise PermissionError("Unregistered broker channel")
        contract = self.authority.get(binding.task_id, require_active=True)
        row = self.authority.record(binding.task_id)
        if row["state"] != "running" or contract.contract_version != binding.contract_version:
            raise PermissionError("Channel is inactive or revoked")
        if row["started_at"] and now() > datetime.fromisoformat(row["started_at"]) + timedelta(
            seconds=contract.limits.max_execution_seconds
        ):
            raise PermissionError("execution budget expired")
        return binding

    def handle(self, channel: ChannelContext, request: BrokerRequest) -> BrokerResponse:
        # Serializes request-id replay and budgets across threads in this single-worker MVP.
        with self.store.lock:
            binding = self.resolve(channel)
            contract = self.authority.get(binding.task_id, require_active=True)
            identity = f"{binding.capsule_id}:{request.request_id}"
            fingerprint = self.store.sign(request.model_dump(mode="json"))
            previous = [
                r["body"]
                for r in self.store.evidence(binding.task_id, "broker")
                if r["identity"] == identity
            ]
            if previous:
                if previous[0]["fingerprint"] != fingerprint:
                    raise ValueError("request id reused with different payload")
                return BrokerResponse.model_validate(previous[0]["response"])
            history = [
                r["body"]["response"]["receipt"]
                for r in self.store.evidence(binding.task_id, "broker")
                if r["body"]["response"]["receipt"]["capsule_id"] == binding.capsule_id
            ]
            reason, result = "OK", None
            verdict: Literal["allowed", "denied"] = "allowed"
            effect: Literal["blocked", "completed", "unknown"] = "completed"
            report: Report | None = None
            try:
                if len(canonical(request.model_dump(mode="json")).encode()) > 16384:
                    raise ValueError("PAYLOAD_TOO_LARGE")
                if len(history) >= 32:
                    raise ValueError("REQUEST_BUDGET_EXCEEDED")
                if request.operation not in contract.allowed_operations:
                    raise ValueError("DENIED_OPERATION")
                if contract.allowed_data_classes != ("synthetic_payroll_aggregate",):
                    raise ValueError("DATA_CLASS_NOT_AUTHORIZED")
                if request.operation == "data.get_department_totals":
                    if request.payload:
                        raise ValueError("INVALID_DATA_PAYLOAD")
                    result = department_totals().model_dump(mode="json")
                elif request.operation == "model.generate_report_draft":
                    payload = ModelRequest.model_validate(request.payload)
                    self.verify_totals(payload.aggregates)
                    if sum(r["operation"] == request.operation for r in history) >= 4:
                        raise ValueError("MODEL_BUDGET_EXCEEDED")
                    result = self.model.choose(payload).model_dump(mode="json")
                elif request.operation == "output.save_department_summary":
                    report = Report.model_validate(request.payload)
                    self.verify_totals(report)
                    if any(
                        r["operation"] == request.operation and r["effect_status"] == "completed"
                        for r in history
                    ):
                        raise ValueError("OUTPUT_ALREADY_RELEASED")
                    if self.coverage_check is None or not self.coverage_check(binding):
                        raise ValueError("REQUIRED_SENSOR_COVERAGE_UNAVAILABLE")
                    result = {"destination": "internal_reports", "report_id": uuid4().hex}
            except (ValidationError, ValueError) as exc:
                verdict, effect = "denied", "blocked"
                reason = (
                    (
                        "OUTPUT_SCHEMA_VIOLATION"
                        if request.operation == "output.save_department_summary"
                        else "BROKER_PAYLOAD_SCHEMA_VIOLATION"
                    )
                    if isinstance(exc, ValidationError)
                    else str(exc)
                )
                report = None
            except ModelUnavailable:
                effect, reason = "unknown", "MODEL_UNAVAILABLE"
            receipt = Receipt(
                receipt_id=uuid4().hex,
                task_id=binding.task_id,
                capsule_id=binding.capsule_id,
                request_id=request.request_id,
                correlation_id=uuid4().hex,
                operation=request.operation,
                verdict=verdict,
                effect_status=effect,
                reason=reason,
                evidence_reference=f"broker-{uuid4().hex}",
                observed_at=now(),
            )
            response = BrokerResponse(receipt=receipt, result=result)
            with self.store.transaction():
                self.store._append(
                    "broker",
                    identity,
                    binding.task_id,
                    {
                        "fingerprint": fingerprint,
                        "response": response.model_dump(mode="json"),
                        "simulated": binding.simulated,
                    },
                )
                if report is not None and result is not None and verdict == "allowed":
                    self.store._append(
                        "report",
                        result["report_id"],
                        binding.task_id,
                        {
                            "report": report.model_dump(mode="json"),
                            "capsule_id": binding.capsule_id,
                            "receipt_id": receipt.receipt_id,
                            "destination": "internal_reports",
                            "simulated": binding.simulated,
                        },
                    )
            return response

    @staticmethod
    def verify_totals(report: Report) -> None:
        expected = department_totals()
        actual = {row.department: row.total for row in report.departments}
        if len(actual) != 3 or actual != {
            row.department: row.total for row in expected.departments
        }:
            raise ValueError("TOTALS_MISMATCH")
