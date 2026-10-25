import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from application.models import Source


@dataclass(frozen=True)
class SensorIdentity:
    token: str
    host_id: str
    sources: tuple[Source, ...]


@dataclass(frozen=True)
class Settings:
    owner_token: str
    runtime_token: str
    integrity_key: str
    database: Path = Path("var/agentguard.sqlite3")
    local_model_enabled: bool = False
    approved_model_digest: str | None = None
    approved_lab_image: str | None = None
    sensors: dict[str, SensorIdentity] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.approved_model_digest is not None and not re.fullmatch(
            r"[a-f0-9]{64}", self.approved_model_digest
        ):
            raise ValueError("Approved local model must have an immutable SHA-256 digest")
        if self.local_model_enabled and self.approved_model_digest is None:
            raise ValueError("Enabling local inference requires the reviewed model digest")
        if self.approved_lab_image is not None and not re.fullmatch(
            r"sha256:[a-f0-9]{64}", self.approved_lab_image
        ):
            raise ValueError("Approved lab image must be an immutable local image ID")
        keys = [self.owner_token, self.runtime_token, self.integrity_key] + [
            s.token for s in self.sensors.values()
        ]
        if any(len(key) < 32 for key in keys) or len(set(keys)) != len(keys):
            raise ValueError(
                "Set distinct owner, runtime, integrity and sensor secrets of at least 32 characters"
            )
        if any("placeholder" in key.lower() or len(set(key)) < 8 for key in keys):
            raise ValueError("Use generated random credentials")

    @classmethod
    def from_env(cls) -> "Settings":
        registry = os.environ.get("AG_SENSOR_REGISTRY")
        sensors = {}
        if registry:
            for sensor_id, record in json.loads(Path(registry).read_text()).items():
                sources = tuple(record["sources"])
                if not set(sources) <= {
                    "host_sensor",
                    "network_sensor",
                    "policy_engine",
                    "sensor_health",
                }:
                    raise ValueError("Sensor cannot impersonate broker/runtime")
                sensors[sensor_id] = SensorIdentity(
                    token=record["token"], host_id=record["host_id"], sources=sources
                )
        return cls(
            database=Path(os.environ.get("AG_DATABASE_PATH", "var/agentguard.sqlite3")),
            owner_token=os.environ.get("AG_OWNER_TOKEN", ""),
            runtime_token=os.environ.get("AG_RUNTIME_TOKEN", ""),
            integrity_key=os.environ.get("AG_INTEGRITY_KEY", ""),
            approved_lab_image=os.environ.get("AG_LAB_IMAGE_ID") or None,
            local_model_enabled=os.environ.get("AG_LOCAL_MODEL_ENABLED") == "true",
            approved_model_digest=os.environ.get("AG_APPROVED_MODEL_DIGEST") or None,
            sensors=sensors,
        )

    def identify(self, authorization: str, role: str) -> str:
        if not authorization.startswith("Bearer "):
            raise PermissionError("Authentication required")
        token = authorization[7:]
        if role == "sensor":
            for sensor_id, sensor in self.sensors.items():
                if hmac.compare_digest(token, sensor.token):
                    return sensor_id
        else:
            expected = self.owner_token if role == "owner" else self.runtime_token
            if hmac.compare_digest(token, expected):
                return "synthetic-finance-owner" if role == "owner" else "trusted-runtime"
        raise PermissionError("Credential not authorized for this interface")

    @staticmethod
    def token_fingerprint(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def rate_bucket(self, peer: str, path: str, authorization: str) -> tuple[str, int]:
        if path in {"/internal/v1/events", "/internal/v1/member2/events", "/internal/v1/coverage"}:
            try:
                sensor_id = self.identify(authorization, "sensor")
            except PermissionError:
                pass
            else:
                # Only authenticated sources get an independent bounded kernel
                # event budget. Rotating invalid tokens cannot obtain this quota.
                return peer + "|sensor|" + sensor_id, 10000
        return peer, 600
