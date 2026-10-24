"""Export the reviewed v1 structural interfaces; semantic checks stay server-side."""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from agentguard.schema import COVERAGE, EFFECTS, EVENT_TYPES, OPERATIONS, SOURCES, VERDICTS


def obj(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def text(maximum=512):
    return {"type": "string", "minLength": 1, "maxLength": maximum}


def nullable(value):
    return {"anyOf": [value, {"type": "null"}]}


def schemas():
    date = {"type": "string", "format": "date-time"}
    version = {"type": "integer", "minimum": 1, "maximum": 1_000_000}
    task = obj({
        "schema_version": {"const": "1.0"}, "task_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},
        "contract_version": version, "approved_by": text(128), "agent_role": text(128), "objective": text(2048),
        "allowed_operations": {"type": "array", "items": {"enum": sorted(OPERATIONS)}, "minItems": 1, "uniqueItems": True},
        "allowed_data_classes": {"const": ["synthetic_payroll_aggregate"]},
        "approved_output_destination": {"const": "internal_reports"}, "output_schema": {"const": "department_summary_v1"},
        "direct_internet_allowed": {"const": False}, "expires_at": date,
        "limits": obj({"max_execution_seconds": {"type": "integer", "minimum": 1, "maximum": 600},
                       "max_memory_mb": {"type": "integer", "minimum": 32, "maximum": 2048},
                       "max_processes": {"type": "integer", "minimum": 4, "maximum": 128}}),
    })
    observation = obj({
        "schema_version": {"const": "1.0"}, "event_id": text(4096), "task_id": text(4096), "contract_version": version,
        "capsule_id": text(4096), "host_id": text(4096), "source": {"enum": sorted(SOURCES)}, "event_type": {"enum": sorted(EVENT_TYPES)},
        "observed_at": date, "received_at": date,
        "process_identity": obj({"pid": nullable({"type": "integer", "minimum": 1, "maximum": 2**31 - 1}),
                                 "start_time": nullable(date), "cgroup_id": nullable(text(4096))}),
        "operation": text(4096), "resource_or_destination": nullable(text(4096)),
        "policy_verdict": {"enum": sorted(VERDICTS)}, "effect_status": {"enum": sorted(EFFECTS)},
        "coverage_status": {"enum": sorted(COVERAGE)}, "correlation_id": nullable(text(4096)),
        "evidence_reference": text(4096), "details": {"type": "object"},
    })
    return {"task-contract-v1.schema.json": task, "security-event-v1.schema.json": observation}


def main():
    for filename, value in schemas().items():
        value = {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": filename.removesuffix(".schema.json"), **value}
        (ROOT / "contracts" / filename).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
