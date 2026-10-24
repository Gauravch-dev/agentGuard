import json
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from application.models import SecurityEvent, TaskContract
from scripts.export_contracts import MODELS, export

ROOT = Path(__file__).resolve().parents[2]


def test_exported_schema_frozen():
    export(check=True)
    for name, _model in MODELS.items():
        jsonschema.Draft202012Validator.check_schema(
            json.loads((ROOT / "contracts" / f"{name}.schema.json").read_text())
        )


def test_handoffs_shared_contract_identical():
    def shared(name):
        text = (ROOT / "docs" / "handoffs" / name).read_text(encoding="utf-8")
        return text.split("## Shared integration contract")[1].split("## References")[0]

    assert shared("AGENTGUARD_MVP_MEMBER_1_APPLICATION.md") == shared(
        "AGENTGUARD_MVP_MEMBER_2_LINUX_PLATFORM.md"
    )


def test_exact_handoff_examples_validate():
    import re

    text = (ROOT / "docs" / "handoffs" / "AGENTGUARD_MVP_MEMBER_2_LINUX_PLATFORM.md").read_text(
        encoding="utf-8"
    )
    examples = [json.loads(block) for block in re.findall(r"```json\s*(.*?)```", text, re.S)]
    for example in examples:
        name = "task_contract" if "allowed_operations" in example else "security_event"
        model = TaskContract if name == "task_contract" else SecurityEvent
        model.model_validate(example)
        jsonschema.validate(
            example, json.loads((ROOT / "contracts" / f"{name}.schema.json").read_text())
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "agent"),
        ("effect_status", "leaked"),
        ("coverage_status", "safe"),
        ("policy_verdict", "safe"),
    ],
)
def test_no_silent_event_enum_extensions(field, value):
    base = dict(
        event_id="e",
        task_id="FIN-1",
        contract_version=1,
        capsule_id="cap",
        host_id="host",
        source="host_sensor",
        event_type="process_exec",
        observed_at="2026-10-24T00:00:00Z",
    )
    base[field] = value
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(base)
