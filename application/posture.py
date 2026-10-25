"""Bounded owner-facing evidence summary. No host paths, credentials or raw snapshots."""

import math
import re
import time
from datetime import datetime
from typing import Any

from application.coverage import coverage_findings
from application.models import Binding, Coverage, now
from application.store import Store


def safe_codes(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    return sorted(
        {
            v
            for v in values[:128]
            if isinstance(v, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", v)
        }
    )


def count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**63 - 1 else None


def owner_posture(
    store: Store,
    task_id: str,
    version: int,
    binding: Binding | None,
    runtime: Any,
    *,
    current: bool,
) -> dict:
    checked = now()
    observations = [
        r
        for r in store.evidence(task_id)
        if (r["kind"] == "event" and r["body"]["event"]["contract_version"] == version)
        or (
            r["kind"] == "coverage"
            and binding is not None
            and r["body"]["capsule_id"] == binding.capsule_id
        )
    ]
    windows = [
        Coverage.model_validate(r["body"])
        for r in store.evidence(task_id, "coverage")
        if binding is not None and r["body"]["capsule_id"] == binding.capsule_id
    ]
    endings = [
        r["body"]["execution_end"]
        for kind in ("termination", "task_result")
        for r in store.evidence(task_id, kind)
        if binding is not None
        and r["body"].get("capsule_id") == binding.capsule_id
        and r["body"].get("descendants_exited")
        and r["body"].get("execution_end")
    ]
    end = max(datetime.fromisoformat(value) for value in endings) if endings else checked
    gaps = coverage_findings(binding, windows, binding.process_start, end) if binding else []
    observer: dict = {
        "connected": False,
        "reasons": ["CONTINUOUS_OBSERVER_UNAVAILABLE"],
        "sources": {},
    }
    supervisor = getattr(runtime, "supervisor", None)
    if current and binding is not None and supervisor is not None:
        try:
            raw = supervisor.status(binding.capsule_id)
            if (
                raw.get("capsule_id") != binding.capsule_id
                or "cg-" + str(raw.get("cgroup_inode")) != binding.cgroup_id
            ):
                raise ValueError("Observer mapping mismatch")
            sources = {}
            for kind in ("process", "hooks", "packet"):
                source = raw.get("sources", {}).get(kind)
                if not isinstance(source, dict):
                    continue
                heartbeat = source.get("last_heartbeat")
                age = None
                if (
                    isinstance(heartbeat, (int, float))
                    and not isinstance(heartbeat, bool)
                    and math.isfinite(heartbeat)
                ):
                    age = time.monotonic() - heartbeat
                if age is not None and age < 0:
                    age = None
                sources[kind] = {
                    "alive": source.get("alive") is True,
                    "health_age_seconds": round(age, 2) if age is not None else None,
                    "fresh": age is not None and age <= 5,
                    **{
                        key: count(source.get(key))
                        for key in ("pending", "gaps", "lost", "export_failures")
                    },
                    "epoch_changed": source.get("epoch_changed") is True,
                }
            observer = {
                "connected": True,
                "reasons": safe_codes(raw.get("reasons")),
                "sources": sources,
                "finished": raw.get("finished") is True,
            }
        except Exception:
            observer["reasons"] = ["OBSERVER_STATUS_UNAVAILABLE"]
    return {
        "contract_version": version,
        "historical": not current,
        "checked_at": checked.isoformat(),
        "protected_execution_ready": False,
        "coverage": {
            "status": "unverified" if not binding or gaps else "covered_interval",
            "windows": len(windows),
            "gaps": [f.model_dump(mode="json") for f in gaps],
            "through": end.isoformat(),
        },
        "last_sensor_receipt": observations[-1]["received_at"] if observations else None,
        "observer": observer,
    }
