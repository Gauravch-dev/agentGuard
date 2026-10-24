"""No network: verifies the optional provider's fixed local boundary and tool parser."""

import json

import httpx
import pytest

from application.model_provider import LocalOllamaModel, ModelUnavailable
from application.models import ModelRequest
from application.synthetic import department_totals


def test_local_model_fixed_target_and_untrusted_choice(monkeypatch):
    original = httpx.Client
    seen = []

    def handle(request):
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        body = json.loads(request.content)
        assert body["model"] == "qwen2.5:7b"
        assert body["options"]["num_predict"] == 1024
        assert "SYN-001" not in request.content.decode()
        seen.append(body)
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps({"operation": "data.get_raw_payroll", "payload": {}})
                }
            },
        )

    def factory(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return original(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    choice = LocalOllamaModel().choose(
        ModelRequest(
            template_id="finance_summary_v1", aggregates=department_totals(), document_id="injected"
        )
    )
    assert choice.operation == "data.get_raw_payroll"  # The broker, not the model, must deny this.
    assert len(seen) == 1


@pytest.mark.parametrize(
    "status,body",
    [(302, ""), (200, "x" * 33000), (200, "invalid json")],
    ids=["redirect", "oversize", "invalid-json"],
)
def test_bad_model_response_never_falls_back(monkeypatch, status, body):
    original = httpx.Client

    def factory(**kwargs):
        return original(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    status, text=body, headers={"Location": "https://example.invalid"}
                )
            ),
            **kwargs,
        )

    monkeypatch.setattr(httpx, "Client", factory)
    with pytest.raises(ModelUnavailable):
        LocalOllamaModel().choose(
            ModelRequest(template_id="finance_summary_v1", aggregates=department_totals())
        )
