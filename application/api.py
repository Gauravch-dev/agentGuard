"""Authenticated owner API and separate trusted sensor/runtime ingestion surfaces."""

import json
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from agentguard.platform import PlatformError
from agentguard.schema import strict_json
from application.authority import Authority
from application.brokers import Broker
from application.config import Settings
from application.coverage import release_coverage_ready
from application.member2_bridge import (
    Member2RuntimeAdapter,
    Member2Transfer,
    translate_member2_event,
)
from application.model_provider import DisabledModel, LocalOllamaModel
from application.models import (
    Binding,
    Completion,
    Coverage,
    CreateTask,
    EmptyRequest,
    EventEnvelope,
    Finding,
    Receipt,
    ReviewNote,
    SecurityEvent,
    now,
)
from application.runtime_adapter import REQUIRED_CONTROLS, RuntimeAdapter, UnavailableRuntime
from application.store import Store
from application.tere import reconcile

ROOT = Path(__file__).resolve().parents[1]


def create_app(settings: Settings | None = None, runtime: RuntimeAdapter | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    runtime = runtime or Member2RuntimeAdapter(approved_image=settings.approved_lab_image)
    store = Store(settings.database, settings.integrity_key)
    authority = Authority(store)

    def release_check(binding: Binding) -> bool:
        row = authority.record(binding.task_id)
        if not row["started_at"]:
            return False
        start = datetime.fromisoformat(row["started_at"])
        receipts = [
            Receipt.model_validate(r["body"]["response"]["receipt"])
            for r in store.evidence(binding.task_id, "broker")
            if r["body"]["response"]["receipt"]["capsule_id"] == binding.capsule_id
        ]
        cutoff = max([start] + [r.observed_at for r in receipts])
        windows = [
            Coverage.model_validate(r["body"]) for r in store.evidence(binding.task_id, "coverage")
        ]
        return release_coverage_ready(binding, windows, start, cutoff, now())

    broker = Broker(
        store,
        authority,
        LocalOllamaModel() if settings.local_model_enabled else DisabledModel(),
        coverage_check=release_check,
    )

    app = FastAPI(
        title="AgentGuard 2.0", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.store, app.state.authority, app.state.broker = store, authority, broker
    app.state.coverage_policy = release_check
    rates: dict[str, deque] = defaultdict(deque)

    def owner(authorization: Annotated[str, Header()] = "") -> str:
        return settings.identify(authorization, "owner")

    def sensor(authorization: Annotated[str, Header()] = "") -> str:
        return settings.identify(authorization, "sensor")

    def platform(authorization: Annotated[str, Header()] = "") -> str:
        return settings.identify(authorization, "runtime")

    @app.exception_handler(PermissionError)
    async def denied(request: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse({"detail": "Authentication or authorization failed"}, status_code=403)

    @app.exception_handler(KeyError)
    async def missing(request: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse({"detail": "Record not found"}, status_code=404)

    @app.exception_handler(ValueError)
    async def invalid(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            {"detail": "Request conflicts with validated state or policy"}, status_code=409
        )

    @app.exception_handler(RequestValidationError)
    async def validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            {"detail": "Request does not match the approved schema"}, status_code=422
        )

    @app.middleware("http")
    async def guard(request: Request, call_next):  # type: ignore[no-untyped-def]
        host = request.headers.get("host", "").split(":")[0]
        if host not in {"127.0.0.1", "localhost", "testserver"}:
            return JSONResponse({"detail": "Local host only"}, status_code=400)
        if request.headers.get("origin") and request.headers["origin"] not in {
            "http://127.0.0.1:8000",
            "http://localhost:8000",
        }:
            return JSONResponse({"detail": "Origin rejected"}, status_code=403)
        peer = request.client.host if request.client else "unknown"
        stamp = time.monotonic()
        if len(rates) >= 4096 and peer not in rates:
            return JSONResponse({"detail": "Rate limit"}, status_code=429)
        window = rates[peer]
        while window and window[0] < stamp - 60:
            window.popleft()
        if len(window) >= 600:
            return JSONResponse({"detail": "Rate limit"}, status_code=429)
        window.append(stamp)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 32768:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
        if body and (
            not request.headers.get("content-type")
            or "application/json" in request.headers.get("content-type", "")
        ):
            try:
                strict_json(bytes(body))
            except ValueError:
                return JSONResponse(
                    {"detail": "Strict JSON required; duplicate keys/non-finite values rejected"},
                    status_code=422,
                )
        request._body = bytes(body)
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            }
        )
        return response

    def binding_for(task_id: str) -> Binding | None:
        contract = authority.get(task_id)
        rows = store.evidence(task_id, "binding")
        matches = [
            Binding.model_validate(r["body"])
            for r in rows
            if r["body"]["contract_version"] == contract.contract_version
        ]
        return matches[-1] if matches else None

    @app.get("/api/v1/health")
    def health() -> dict:
        return {
            "application": "ready",
            "runtime_connected": not isinstance(
                runtime, (UnavailableRuntime, Member2RuntimeAdapter)
            ),
            "platform_adapter": "member2"
            if isinstance(runtime, Member2RuntimeAdapter)
            else "custom",
            "local_model_enabled": settings.local_model_enabled,
            "live_isolation_verified": False,
        }

    @app.get("/api/v1/platform")
    def platform_status(principal: str = Depends(owner)) -> dict:
        if isinstance(runtime, Member2RuntimeAdapter):
            return runtime.capabilities()
        return {
            "protected_execution_ready": False,
            "reason": "Custom runtime; inspect per-task readiness evidence",
        }

    @app.post("/api/v1/tasks/{task_id}/isolation-lab")
    def isolation_lab(
        task_id: str, payload: EmptyRequest = EmptyRequest(), principal: str = Depends(owner)
    ) -> dict:
        contract = authority.get(task_id, require_active=True)
        if authority.record(task_id)["state"] != "approved" or not isinstance(
            runtime, Member2RuntimeAdapter
        ):
            raise ValueError("Fixed lab requires approved task and Member 2 adapter")
        try:
            lab_result = runtime.isolation_lab(contract)
            store.append("platform_lab", uuid4().hex, task_id, lab_result)
            return {
                "mode": "isolation-lab",
                "result": lab_result,
                "protected_execution_ready": False,
            }
        except (PlatformError, OSError) as exc:
            store.append(
                "platform_lab",
                uuid4().hex,
                task_id,
                {
                    "mode": "isolation-lab",
                    "completed": False,
                    "reason": str(exc)[:1024],
                    "protected_execution_ready": False,
                },
            )
            raise HTTPException(
                503, "Fixed isolation lab unavailable; inspect platform evidence"
            ) from exc

    @app.post("/api/v1/tasks", status_code=201)
    def create(payload: CreateTask, principal: str = Depends(owner)) -> dict:
        contract = authority.create(principal)
        return {"contract": contract, "state": "approved"}

    @app.get("/api/v1/tasks")
    def tasks(principal: str = Depends(owner)) -> list[dict]:
        with store.lock:
            rows = store.db.execute(
                "SELECT task_id,version,state,created_at FROM task_contracts AS t WHERE version=(SELECT MAX(version) FROM task_contracts WHERE task_id=t.task_id) ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        return [dict(row) for row in rows]

    @app.get("/api/v1/tasks/{task_id}")
    def task(task_id: str, principal: str = Depends(owner)) -> dict:
        row = authority.record(task_id)
        return {
            "contract": authority.get(task_id),
            "state": row["state"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "ended_at": row["ended_at"],
            "binding": binding_for(task_id),
            "readiness": [r["body"] for r in store.evidence(task_id, "readiness")],
        }

    @app.post("/api/v1/tasks/{task_id}/revisions", status_code=201)
    def revise(task_id: str, principal: str = Depends(owner)) -> dict:
        return {"contract": authority.revise(task_id, principal), "state": "approved"}

    @app.post("/api/v1/tasks/{task_id}/launch")
    def launch(task_id: str, principal: str = Depends(owner)) -> dict:
        with store.lock:
            contract = authority.get(task_id, require_active=True)
            authority.transition(task_id, "launch_requested")
            requested_at = now()
            try:
                result = runtime.launch(contract)
                store.append("readiness", uuid4().hex, task_id, result.model_dump(mode="json"))
                if isinstance(runtime, Member2RuntimeAdapter):
                    store.append(
                        "platform_preflight",
                        uuid4().hex,
                        task_id,
                        {"checks": runtime.last_preflight, "protected_execution_ready": False},
                    )
                binding = result.binding
                valid = (
                    result.readiness_passed
                    and result.state == "running"
                    and REQUIRED_CONTROLS <= set(result.controls)
                    and not result.simulated
                    and binding is not None
                )
                if valid and binding is not None:
                    valid = (
                        not binding.simulated
                        and binding.task_id == task_id
                        and binding.contract_version == contract.contract_version
                        and binding.host_id in {s.host_id for s in settings.sensors.values()}
                        and requested_at - timedelta(seconds=5)
                        <= binding.process_start
                        <= binding.registered_at
                        <= now() + timedelta(seconds=5)
                    )
                    with store.lock:
                        prior = store.db.execute(
                            "SELECT body FROM evidence WHERE kind='binding'"
                        ).fetchall()
                    valid = valid and not any(
                        json.loads(r[0])["capsule_id"] == binding.capsule_id
                        or json.loads(r[0])["channel_id"] == binding.channel_id
                        for r in prior
                    )
                if not valid or binding is None:
                    if binding:
                        # Fail closed, request cleanup; never claim termination without inspection.
                        cleanup = runtime.terminate(binding.capsule_id)
                        store.append(
                            "termination", uuid4().hex, task_id, cleanup.model_dump(mode="json")
                        )
                    authority.transition(task_id, "failed")
                    raise HTTPException(
                        503,
                        "Verified Linux readiness and trusted binding required; see readiness evidence",
                    )
                store.append(
                    "binding", binding.capsule_id, task_id, binding.model_dump(mode="json")
                )
                authority.transition(task_id, "running")
                return {"state": "running", "binding": binding}
            except HTTPException:
                raise
            except Exception as exc:
                if authority.record(task_id)["state"] == "launch_requested":
                    authority.transition(task_id, "failed")
                store.append(
                    "runtime_error", uuid4().hex, task_id, {"reason": "RUNTIME_LAUNCH_FAILED"}
                )
                raise HTTPException(
                    503, "Runtime launch failed; inspect platform evidence"
                ) from exc

    @app.post("/api/v1/tasks/{task_id}/terminate")
    def terminate(task_id: str, principal: str = Depends(owner)) -> dict:
        binding = binding_for(task_id)
        if binding is None or authority.record(task_id)["state"] != "running":
            raise ValueError("No active capsule")
        result = runtime.terminate(binding.capsule_id)
        inspected = runtime.inspect(binding.capsule_id)
        store.append(
            "termination",
            uuid4().hex,
            task_id,
            {
                "request": result.model_dump(mode="json"),
                "inspection": inspected.model_dump(mode="json"),
            },
        )
        if (
            inspected.binding != binding
            or inspected.simulated
            or not inspected.descendants_exited
            or inspected.state not in {"completed", "failed", "interrupted"}
        ):
            raise HTTPException(409, "Process/cgroup exit not independently verified")
        authority.transition(task_id, "interrupted")
        return {"state": "interrupted", "descendants_exited": True}

    @app.post("/internal/v1/tasks/{task_id}/completion")
    def complete(task_id: str, payload: Completion, principal: str = Depends(platform)) -> dict:
        binding = binding_for(task_id)
        if binding is None or binding.capsule_id != payload.capsule_id:
            raise ValueError("Runtime binding mismatch")
        inspected = runtime.inspect(binding.capsule_id)
        if (
            inspected.binding != binding
            or inspected.simulated
            or not inspected.descendants_exited
            or not payload.descendants_exited
            or inspected.state != payload.state
        ):
            raise ValueError("Runtime completion not verified")
        if payload.state == "completed" and not any(
            r["body"]["capsule_id"] == binding.capsule_id for r in store.evidence(task_id, "report")
        ):
            raise ValueError("Business success requires trusted output receipt")
        authority.transition(task_id, payload.state)
        store.append("task_result", uuid4().hex, task_id, payload.model_dump(mode="json"))
        return {"state": payload.state}

    def ingest_canonical(
        payload: SecurityEvent, sensor_id: str, metadata: dict | None = None
    ) -> dict:
        with store.lock:
            identity = settings.sensors[sensor_id]
            binding = binding_for(payload.task_id)
            if (
                payload.source not in identity.sources
                or payload.host_id != identity.host_id
                or payload.source in {"trusted_broker", "runtime"}
            ):
                raise PermissionError("Untrusted event source")
            if (
                payload.policy_verdict in {"allowed", "denied"}
                and payload.source != "policy_engine"
            ):
                raise PermissionError("Only registered policy decision point may assert verdicts")
            if (
                binding is None
                or binding.capsule_id != payload.capsule_id
                or binding.host_id != payload.host_id
                or binding.contract_version != payload.contract_version
            ):
                raise PermissionError("Unregistered capsule mapping")
            existing = [
                r
                for r in store.evidence(payload.task_id, "event")
                if r["identity"] == f"{sensor_id}:{payload.event_id}"
            ]
            if existing:
                if existing[0]["body"]["event"] != payload.model_dump(mode="json"):
                    store.append(
                        "ingestion_conflict",
                        uuid4().hex,
                        payload.task_id,
                        {"event_id": payload.event_id, "sensor_id": sensor_id},
                    )
                    raise ValueError("Conflicting duplicate event")
                return {"accepted": True, "duplicate": True}
            envelope = EventEnvelope(event=payload, sensor_id=sensor_id, received_at=now())
            with store.transaction():
                store._append(
                    "event",
                    f"{sensor_id}:{payload.event_id}",
                    payload.task_id,
                    envelope.model_dump(mode="json"),
                )
                if metadata is not None:
                    store._append(
                        "member2_metadata",
                        f"{sensor_id}:{payload.event_id}",
                        payload.task_id,
                        metadata,
                    )
            return {"accepted": True, "duplicate": False}

    @app.post("/internal/v1/events")
    def ingest(payload: SecurityEvent, sensor_id: str = Depends(sensor)) -> dict:
        return ingest_canonical(payload, sensor_id)

    @app.post("/internal/v1/member2/events")
    def ingest_member2(payload: Member2Transfer, sensor_id: str = Depends(sensor)) -> dict:
        event, metadata = translate_member2_event(payload.event, sensor_id)
        return ingest_canonical(event, sensor_id, metadata)

    @app.post("/internal/v1/coverage")
    def ingest_coverage(payload: Coverage, sensor_id: str = Depends(sensor)) -> dict:
        identity = settings.sensors[sensor_id]
        binding = binding_for(payload.task_id)
        if (
            payload.sensor_id != sensor_id
            or payload.source not in identity.sources
            or payload.simulated
            or binding is None
            or payload.capsule_id != binding.capsule_id
            or identity.host_id != binding.host_id
            or payload.end > now() + timedelta(seconds=5)
        ):
            raise PermissionError("Invalid coverage provenance")
        store.append(
            "coverage",
            f"{sensor_id}:{payload.coverage_id}",
            payload.task_id,
            payload.model_dump(mode="json"),
        )
        return {"accepted": True}

    @app.get("/api/v1/tasks/{task_id}/events")
    def events(task_id: str, principal: str = Depends(owner)) -> list[dict]:
        authority.get(task_id)
        if not store.verify_chain():
            raise HTTPException(503, "Evidence integrity check failed")
        return store.evidence(task_id)

    @app.get("/api/v1/tasks/{task_id}/result")
    def result(task_id: str, principal: str = Depends(owner)) -> dict:
        row = authority.record(task_id)
        integrity = store.verify_chain()
        try:
            contract = authority.get(task_id)
        except ValueError:
            contract, integrity = None, False
        binding = binding_for(task_id) if integrity else None
        receipts = [
            Receipt.model_validate(r["body"]["response"]["receipt"])
            for r in store.evidence(task_id, "broker")
            if integrity
            and binding
            and r["body"]["response"]["receipt"]["capsule_id"] == binding.capsule_id
        ]
        start = datetime.fromisoformat(row["started_at"] or row["created_at"])
        end = datetime.fromisoformat(row["ended_at"]) if row["ended_at"] else now()
        findings = reconcile(
            contract,
            binding,
            receipts,
            [
                EventEnvelope.model_validate(r["body"])
                for r in store.evidence(task_id, "event")
                if integrity and r["body"]["event"]["contract_version"] == row["version"]
            ],
            [
                Coverage.model_validate(r["body"])
                for r in store.evidence(task_id, "coverage")
                if integrity
            ],
            start,
            end,
            integrity,
        )
        conflicts = store.evidence(task_id, "ingestion_conflict")
        if conflicts:
            findings.append(
                Finding(
                    classification="Unverified",
                    reason_code="CONFLICTING_DUPLICATE",
                    explanation="Ingestion rejected conflicting event records.",
                    evidence_references=tuple(r["identity"] for r in conflicts),
                )
            )
        encoded = [f.model_dump(mode="json") for f in findings]
        fingerprint = store.sign(encoded)
        if integrity:
            store.append(
                "assessment",
                f"{task_id}:v{row['version']}:{fingerprint}",
                task_id,
                {"findings": encoded, "contract_version": row["version"]},
            )
        return {
            "business_outcome": row["state"],
            "findings": encoded,
            "reports": [
                r["body"]
                for r in store.evidence(task_id, "report")
                if binding and r["body"]["capsule_id"] == binding.capsule_id
            ],
            "integrity_verified": integrity,
            "simulated": binding.simulated if binding else False,
        }

    @app.post("/api/v1/tasks/{task_id}/notes", status_code=201)
    def note(task_id: str, payload: ReviewNote, principal: str = Depends(owner)) -> dict:
        authority.get(task_id)
        note_id = uuid4().hex
        store.append("review_note", note_id, task_id, {"author": principal, "text": payload.text})
        return {"note_id": note_id}

    dist = ROOT / "dashboard" / "application" / "dist"
    if dist.exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/", include_in_schema=False)
        def dashboard() -> FileResponse:
            return FileResponse(dist / "index.html")

    return app
