"""Strict version 1 interfaces shared by the authority, runtime and collectors."""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from uuid import uuid4

OPERATIONS = {
    "data.get_department_totals",
    "model.generate_report_draft",
    "output.save_department_summary",
}
SOURCES = {"host_sensor", "network_sensor", "trusted_broker", "policy_engine", "runtime", "sensor_health"}
EVENT_TYPES = {
    "process_exec", "process_exit", "file_access", "connection_attempt", "egress_flow",
    "broker_request", "broker_release", "policy_denial", "sensor_health", "runtime_lifecycle",
}
VERDICTS = {"allowed", "denied", "not_applicable", "unknown"}
EFFECTS = {"attempted", "blocked", "observed", "completed", "unknown"}
COVERAGE = {"complete", "partial", "unavailable", "unknown"}
TASK_FIELDS = {
    "schema_version", "task_id", "contract_version", "approved_by", "agent_role", "objective",
    "allowed_operations", "allowed_data_classes", "approved_output_destination", "output_schema",
    "direct_internet_allowed", "expires_at", "limits",
}
EVENT_FIELDS = {
    "schema_version", "event_id", "task_id", "contract_version", "capsule_id", "host_id", "source",
    "event_type", "observed_at", "received_at", "process_identity", "operation",
    "resource_or_destination", "policy_verdict", "effect_status", "coverage_status",
    "correlation_id", "evidence_reference", "details",
}


class ValidationError(ValueError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def timestamp() -> str:
    return utcnow().isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("invalid timestamp") from exc
    if result.tzinfo is None:
        raise ValidationError("timestamp requires a timezone")
    return result


def canonical(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValidationError("value is not bounded valid JSON") from exc


def strict_json(raw: str | bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValidationError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject(value):
        raise ValidationError(f"non-finite JSON number: {value}")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValidationError(str(exc)) from exc


def exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValidationError(f"{label}: expected exactly {sorted(keys)}")


def text_value(value, label, maximum=512):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValidationError(f"invalid {label}")


def integer(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValidationError(f"{label} must be an integer in [{low}, {high}]")


def validate_contract(value: dict, *, check_expiry=True) -> dict:
    exact_keys(value, TASK_FIELDS, "task contract")
    if value["schema_version"] != "1.0":
        raise ValidationError("unsupported contract schema")
    if not isinstance(value["task_id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value["task_id"]):
        raise ValidationError("invalid task_id")
    integer(value["contract_version"], "contract_version", 1, 1_000_000)
    for name in ("approved_by", "agent_role", "objective"):
        text_value(value[name], name, 2048 if name == "objective" else 128)
    ops = value["allowed_operations"]
    if not isinstance(ops, list) or not ops or any(not isinstance(op, str) or op not in OPERATIONS for op in ops) or len(ops) != len(set(ops)):
        raise ValidationError("unsupported or duplicate operations")
    if value["allowed_data_classes"] != ["synthetic_payroll_aggregate"]:
        raise ValidationError("only synthetic payroll aggregates are implemented")
    if value["approved_output_destination"] != "internal_reports" or value["output_schema"] != "department_summary_v1":
        raise ValidationError("unsupported output destination/schema")
    if value["direct_internet_allowed"] is not False:
        raise ValidationError("direct internet is forbidden")
    if check_expiry and parse_time(value["expires_at"]) <= utcnow():
        raise ValidationError("contract has expired")
    parse_time(value["expires_at"])
    exact_keys(value["limits"], {"max_execution_seconds", "max_memory_mb", "max_processes"}, "limits")
    for name, low, high in (("max_execution_seconds", 1, 600), ("max_memory_mb", 32, 2048), ("max_processes", 4, 128)):
        integer(value["limits"][name], name, low, high)
    return strict_json(canonical(value))


def validate_event(value: dict) -> dict:
    exact_keys(value, EVENT_FIELDS, "event")
    if value["schema_version"] != "1.0":
        raise ValidationError("unsupported event schema")
    for name, allowed in (("source", SOURCES), ("event_type", EVENT_TYPES), ("policy_verdict", VERDICTS), ("effect_status", EFFECTS), ("coverage_status", COVERAGE)):
        if not isinstance(value[name], str) or value[name] not in allowed:
            raise ValidationError(f"invalid {name}")
    for name in ("event_id", "task_id", "capsule_id", "host_id", "operation", "evidence_reference"):
        text_value(value[name], name, 4096)
    integer(value["contract_version"], "contract_version", 1, 1_000_000)
    for name in ("observed_at", "received_at"):
        parse_time(value[name])
    exact_keys(value["process_identity"], {"pid", "start_time", "cgroup_id"}, "process_identity")
    process = value["process_identity"]
    if process["pid"] is not None:
        integer(process["pid"], "pid", 1, 2**31 - 1)
    if process["start_time"] is not None:
        parse_time(process["start_time"])
    if process["cgroup_id"] is not None:
        text_value(process["cgroup_id"], "cgroup_id", 4096)
    for name in ("resource_or_destination", "correlation_id"):
        if value[name] is not None:
            text_value(value[name], name, 4096)
    if not isinstance(value["details"], dict):
        raise ValidationError("details must be an object")
    if len(canonical(value).encode()) > 65_536:
        raise ValidationError("event too large")
    return strict_json(canonical(value))


def event(*, task_id, contract_version, capsule_id, source, event_type, operation,
          host_id="local-workbench", resource=None, verdict="not_applicable", effect="unknown",
          coverage="unavailable", correlation_id=None, details=None, process_identity=None,
          observed_at=None, evidence_reference=None, event_id=None):
    identity = event_id or str(uuid4())
    return validate_event({
        "schema_version": "1.0", "event_id": identity, "task_id": task_id,
        "contract_version": contract_version, "capsule_id": capsule_id, "host_id": host_id,
        "source": source, "event_type": event_type, "observed_at": observed_at or timestamp(),
        "received_at": timestamp(), "process_identity": process_identity or {"pid": None, "start_time": None, "cgroup_id": None},
        "operation": operation, "resource_or_destination": resource, "policy_verdict": verdict,
        "effect_status": effect, "coverage_status": coverage, "correlation_id": correlation_id,
        "evidence_reference": evidence_reference or f"journal:{identity}", "details": details or {},
    })


def finite_amount(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0 or value > 10**12:
        raise ValidationError("invalid amount")
    return value
