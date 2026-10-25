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
        if request.url.path == "/api/tags":
            return httpx.Response(
                200, json={"models": [{"name": "qwen2.5:7b", "digest": "a" * 64}]}
            )
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
    choice = LocalOllamaModel("a" * 64).choose(
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
                lambda request: (
                    httpx.Response(
                        200, json={"models": [{"name": "qwen2.5:7b", "digest": "a" * 64}]}
                    )
                    if request.url.path == "/api/tags"
                    else httpx.Response(
                        status, text=body, headers={"Location": "https://example.invalid"}
                    )
                )
            ),
            **kwargs,
        )

    monkeypatch.setattr(httpx, "Client", factory)
    with pytest.raises(ModelUnavailable):
        LocalOllamaModel("a" * 64).choose(
            ModelRequest(template_id="finance_summary_v1", aggregates=department_totals())
        )


@pytest.mark.parametrize("change_after_inference", [False, True])
def test_model_digest_mismatch_never_returns_a_choice(monkeypatch, change_after_inference):
    original = httpx.Client
    calls = []

    def handle(request):
        calls.append(request.url.path)
        if request.url.path == "/api/tags":
            digest = "a" * 64 if change_after_inference and len(calls) == 1 else "b" * 64
            return httpx.Response(200, json={"models": [{"name": "qwen2.5:7b", "digest": digest}]})
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {"operation": "output.save_department_summary", "payload": {}}
                    )
                }
            },
        )

    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs)
    )
    with pytest.raises(ModelUnavailable):
        LocalOllamaModel("a" * 64).choose(
            ModelRequest(template_id="finance_summary_v1", aggregates=department_totals())
        )
    assert ("/api/chat" in calls) is change_after_inference


def test_unpinned_local_model_is_refused():
    with pytest.raises(ValueError):
        LocalOllamaModel()
