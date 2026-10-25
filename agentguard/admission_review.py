"""Live, fail-closed host review; snapshots and owner flags cannot grant admission.

The continuous sensor supervisor is intentionally required as a trusted in-process
provider. Its absence is a refusal, even when all effective Docker checks pass.
"""

import re
import stat
from pathlib import Path

import httpx

from agentguard.capsules import ENTRYPOINT, deadline_reached
from agentguard.platform import verify_inspect
from agentguard.transport import process_identity


class LiveAdmissionReview:
    def __init__(self, controller, contract_lookup, *, model_digest=None, sensor_review=None):
        if model_digest is not None and not re.fullmatch(r"[a-f0-9]{64}", model_digest):
            raise ValueError("Approved immutable Ollama digest required")
        self.controller, self.contract_lookup = controller, contract_lookup
        self.model_digest, self.sensor_review = model_digest, sensor_review
        self.last_reasons = []

    def reasons(self, value):
        reasons = []
        if value["image_id"] != self.controller.image_id:
            reasons.append("FINANCE_IMAGE_MISMATCH")
        if value["requested_stop"] or deadline_reached(value):
            reasons.append("WORKLOAD_EXPIRED_OR_REVOKED")
        contract = self.contract_lookup(value["task_id"])
        if contract["contract_version"] != value["contract_version"]:
            reasons.append("CONTRACT_VERSION_MISMATCH")
        effective = self.controller.lab.inspect(value["container_id"])
        effective["Config"]["Entrypoint"] = (effective["Config"].get("Entrypoint") or []) + (
            effective["Config"].get("Cmd") or []
        )
        effective["Config"]["Cmd"] = []
        failures = verify_inspect(
            effective,
            contract,
            self.controller.image_id,
            capsule_mount=Path(value["channel_directory"]),
            entrypoint=ENTRYPOINT,
        )
        if failures:
            reasons.append("CURRENT_EFFECTIVE_PROFILE_REFUSED")
        identity = value["identity"]
        expected = {key: identity[key] for key in ("pid", "start_ticks", "cgroup")}
        if not effective["State"]["Running"] or effective["State"]["Pid"] != identity["pid"]:
            reasons.append("CURRENT_RUNTIME_NOT_RUNNING")
        if process_identity(identity["pid"]) != expected:
            reasons.append("PROCESS_IDENTITY_CHANGED")
        cgroup = self.controller.lab._cgroup(identity["pid"])
        if cgroup.stat().st_ino != identity["cgroup_inode"]:
            reasons.append("CGROUP_IDENTITY_CHANGED")
        if not stat.S_ISSOCK((Path(value["channel_directory"]) / "broker.sock").stat().st_mode):
            reasons.append("PRIVATE_BROKER_SOCKET_UNAVAILABLE")
        if self.sensor_review is None:
            reasons.append("CONTINUOUS_SENSOR_SUPERVISION_UNAVAILABLE")
        else:
            # Must include scope, loss/reset/export, clock and current workload
            # identity checks from the trusted live collector supervisor. There is
            # deliberately no file/HTTP/owner-controlled acceptance boolean.
            reasons.extend(self.sensor_review(value))
        if self.model_digest is None:
            reasons.append("APPROVED_MODEL_DIGEST_UNCONFIGURED")
        else:
            with httpx.Client(trust_env=False, follow_redirects=False, timeout=3) as client:
                response = client.get("http://127.0.0.1:11434/api/tags")
                response.raise_for_status()
                if len(response.content) > 32768:
                    raise ValueError("Bounded model registry required")
                models = response.json()["models"]
                loaded_response = client.get("http://127.0.0.1:11434/api/ps")
                loaded_response.raise_for_status()
                if len(loaded_response.content) > 32768:
                    raise ValueError("Bounded model status required")
                loaded = loaded_response.json()["models"]
            matches = [model for model in models if model["name"] == "qwen2.5:7b"]
            if len(matches) != 1 or matches[0]["digest"] != self.model_digest:
                reasons.append("CURRENT_MODEL_DIGEST_MISMATCH")
            if not any(
                model.get("name") == "qwen2.5:7b" and model.get("digest") == self.model_digest
                for model in loaded
            ):
                reasons.append("APPROVED_MODEL_NOT_LOADED")
        # Re-read after profile/provider checks: neither a passing old lab nor a
        # process sampled before a slow model/sensor request is current proof.
        if (
            process_identity(identity["pid"]) != expected
            or cgroup.stat().st_ino != identity["cgroup_inode"]
        ):
            reasons.append("IDENTITY_CHANGED_DURING_REVIEW")
        if deadline_reached(value):
            reasons.append("DEADLINE_REACHED_DURING_REVIEW")
        return reasons

    def __call__(self, value):
        try:
            self.last_reasons = self.reasons(value)
        except Exception:
            # Missing kernel/daemon/model/collector proof is a hold, never approval.
            self.last_reasons = ["LIVE_PLATFORM_REVIEW_UNAVAILABLE"]
        return not self.last_reasons
