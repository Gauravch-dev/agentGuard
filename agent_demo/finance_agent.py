"""Untrusted Finance Agent. Package only agent_demo in Member 2's capsule."""

import json
import socket
import time
from pathlib import Path
from typing import Protocol
from uuid import uuid4


class BrokerClient(Protocol):
    def call(self, operation: str, payload: dict) -> dict: ...


class BrokerRejected(RuntimeError):
    def __init__(self, reason: str):
        super().__init__("Broker rejected or could not complete operation")
        self.reason = reason


class UnixBrokerClient:
    def __init__(self, path: Path):
        self.path = path

    def call(self, operation: str, payload: dict) -> dict:
        request = {
            "schema_version": "1.0",
            "request_id": uuid4().hex,
            "operation": operation,
            "payload": payload,
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(40)
            channel.connect(str(self.path))
            channel.sendall(json.dumps(request).encode() + b"\n")
            raw = bytearray()
            while b"\n" not in raw:
                chunk = channel.recv(4096)
                if not chunk or len(raw) + len(chunk) > 32768:
                    raise RuntimeError("Invalid broker response")
                raw.extend(chunk)
        response = json.loads(raw)
        if response.get("receipt", {}).get("effect_status") != "completed":
            raise BrokerRejected(response.get("receipt", {}).get("reason", "INVALID_RESPONSE"))
        return response["result"]


def run(client: BrokerClient, document_id: str = "benign") -> dict:
    aggregates = client.call("data.get_department_totals", {})
    choice = client.call(
        "model.generate_report_draft",
        {"template_id": "finance_summary_v1", "aggregates": aggregates, "document_id": document_id},
    )
    # The real model chooses the next action; broker remains the authorizer.
    for attempt in range(4):
        try:
            # Each call uses a new request ID. Replaying a held request must keep
            # its original denied receipt, even when coverage later recovers.
            result = client.call(choice["operation"], choice["payload"])
            break
        except BrokerRejected as exc:
            if (
                choice["operation"] != "output.save_department_summary"
                or exc.reason != "REQUIRED_SENSOR_COVERAGE_UNAVAILABLE"
                or attempt == 3
            ):
                raise
            time.sleep(1)
    if choice["operation"] != "output.save_department_summary":
        raise RuntimeError("Agent did not produce the authorized report")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--document", choices=["benign", "injected"], default="benign")
    args = parser.parse_args()
    print(json.dumps(run(UnixBrokerClient(args.socket), args.document)))
