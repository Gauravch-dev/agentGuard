"""Trusted services; request fields never select the caller's task identity."""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from uuid import uuid4

from .authority import Authority
from .schema import ValidationError, canonical, event, exact_keys, finite_amount
from .store import Store

# Synthetic input stays in the trusted service. Agents receive aggregates only.
PAYROLL = (("Engineering", 42000), ("Engineering", 38000), ("Finance", 31000), ("Finance", 29000), ("Operations", 26000))


def department_summary():
    totals = {}
    for department, salary in PAYROLL:
        totals[department] = totals.get(department, 0) + salary
    return {"departments": [{"department": name, "total": total} for name, total in sorted(totals.items())], "currency": "INR"}


class BrokerDenied(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Binding:
    task_id: str
    contract_version: int
    capsule_id: str
    host_id: str
    mode: str


class BrokerSession:
    """Created by trusted control plane or socket authorizer, never JSON input."""

    def __init__(self, store: Store, authority: Authority, binding: Binding, *, coverage_check=None, model_provider=None):
        self.store, self.authority, self.binding = store, authority, binding
        self.coverage_check = coverage_check or (lambda: False)
        self.model_provider = model_provider
        self._lock = threading.RLock()
        self._revoked = False
        self._calls, self._model_calls = 0, 0
        self._started = time.monotonic()

    def revoke(self):
        with self._lock:
            self._revoked = True

    def _record(self, operation, *, verdict, effect, correlation_id, reason=None, released=False):
        b = self.binding
        self.store.append(event(
            task_id=b.task_id, contract_version=b.contract_version, capsule_id=b.capsule_id,
            host_id=b.host_id, source="trusted_broker",
            event_type="broker_release" if released else "broker_request", operation=operation,
            resource="internal_reports" if operation == "output.save_department_summary" else None,
            verdict=verdict, effect=effect, coverage="complete", correlation_id=correlation_id,
            details={"reason": reason, "execution_mode": b.mode, "coverage_scope": "this broker decision only"},
        ))

    def request(self, request: dict):
        with self._lock:
            correlation = str(uuid4())
            # Do not echo potentially secret payloads or caller-supplied URLs into evidence.
            raw_operation = request.get("operation") if isinstance(request, dict) else None
            operation = raw_operation if isinstance(raw_operation, str) and 0 < len(raw_operation) <= 128 else "invalid_request"
            try:
                exact_keys(request, {"schema_version", "operation", "payload"}, "broker request")
                if request["schema_version"] != "1.0":
                    raise ValidationError("unsupported protocol")
                if len(canonical(request).encode()) > 16_384:
                    raise ValidationError("request too large")
                if self._revoked:
                    raise BrokerDenied("channel_revoked")
                contract = self.authority.load(self.binding.task_id, self.binding.contract_version)
                if time.monotonic() - self._started >= contract["limits"]["max_execution_seconds"]:
                    raise BrokerDenied("execution_deadline_exceeded")
                self._calls += 1
                if self._calls > 32:
                    raise BrokerDenied("request_budget_exhausted")
                if operation not in contract["allowed_operations"]:
                    raise BrokerDenied("operation_not_authorized")
                payload = request["payload"]
                if operation == "data.get_department_totals":
                    exact_keys(payload, set(), "aggregate request")
                    result = department_summary()
                elif operation == "output.save_department_summary":
                    self._validate_summary(payload)
                    if self.binding.mode != "policy-harness" and not self.coverage_check():
                        raise BrokerDenied("required_sensor_coverage_unavailable")
                    # Reconstruct the release from trusted aggregates; avoid using
                    # caller ordering or equivalent numeric encodings as output.
                    self.store.save_report(self.binding.capsule_id, department_summary())
                    result = {"saved": True, "destination": contract["approved_output_destination"]}
                elif operation == "model.generate_report_draft":
                    exact_keys(payload, {"template_id", "aggregates"}, "model request")
                    if payload["template_id"] != "department_summary_v1":
                        raise BrokerDenied("unapproved_prompt_template")
                    self._validate_summary(payload["aggregates"])
                    self._model_calls += 1
                    if self._model_calls > 2:
                        raise BrokerDenied("model_request_budget_exhausted")
                    if self.model_provider is None:
                        raise BrokerDenied("model_provider_not_configured")
                    # Provider receives only a server-generated template and trusted aggregates.
                    # Provider responses are drafts and are never accepted as released reports.
                    result = {"draft": self.model_provider(department_summary()), "released": False}
                    if not isinstance(result["draft"], str) or len(result["draft"]) > 4096:
                        raise BrokerDenied("invalid_model_response")
                else:
                    raise BrokerDenied("operation_not_implemented")
            except (BrokerDenied, ValidationError, KeyError) as exc:
                reason = exc.reason if isinstance(exc, BrokerDenied) else "invalid_or_expired_request_context"
                self._record(operation, verdict="denied", effect="blocked", correlation_id=correlation, reason=reason)
                raise BrokerDenied(reason) from exc
            except Exception:
                # Failure is not an enforcement denial or a completed effect.
                self._record(operation, verdict="unknown", effect="unknown", correlation_id=correlation, reason="service_failure")
                raise
            self._record(operation, verdict="allowed", effect="completed", correlation_id=correlation, released=True)
            return {"schema_version": "1.0", "correlation_id": correlation, "result": result}

    @staticmethod
    def _validate_summary(payload):
        exact_keys(payload, {"departments", "currency"}, "summary")
        if payload["currency"] != "INR" or not isinstance(payload["departments"], list):
            raise BrokerDenied("invalid_summary_schema")
        if len(payload["departments"]) != len(department_summary()["departments"]):
            raise BrokerDenied("aggregate_mismatch")
        seen = set()
        for item in payload["departments"]:
            exact_keys(item, {"department", "total"}, "department")
            if not isinstance(item["department"], str) or item["department"] in seen:
                raise BrokerDenied("invalid_department")
            seen.add(item["department"])
            finite_amount(item["total"])
        ordered = sorted(payload["departments"], key=lambda row: row["department"])
        if ordered != department_summary()["departments"]:
            raise BrokerDenied("aggregate_mismatch")


def request(operation, payload):
    return {"schema_version": "1.0", "operation": operation, "payload": payload}
