"""Generate contracts from reviewed typed models; --check detects schema drift."""

import argparse
import json
from pathlib import Path

from application.member2_bridge import Member2Transfer
from application.models import (
    Binding,
    BrokerRequest,
    BrokerResponse,
    Coverage,
    RuntimeResult,
    SecurityEvent,
    TaskContract,
)

ROOT = Path(__file__).resolve().parents[1]
MODELS = {
    "task_contract": TaskContract,
    "security_event": SecurityEvent,
    "broker_request": BrokerRequest,
    "broker_response": BrokerResponse,
    "capsule_binding": Binding,
    "coverage": Coverage,
    "runtime_result": RuntimeResult,
    "member2_transfer": Member2Transfer,
}


def export(check: bool = False) -> None:
    for name, model in MODELS.items():
        target = ROOT / "contracts" / f"{name}.schema.json"
        schema = model.model_json_schema()
        if name == "member2_transfer":
            schema["properties"]["event"] = {"$ref": "security-event-v1.schema.json"}
        text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        if check:
            if not target.exists() or target.read_text(encoding="utf-8") != text:
                raise SystemExit(f"Schema drift: {target.name}")
        else:
            target.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    export(parser.parse_args().check)
