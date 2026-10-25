"""Save actual Linux component versions without usernames, tokens or raw arguments."""

import json
import platform
import sys
from pathlib import Path

import httpx

from agentguard.platform import command, host_audit
from agentguard.schema import timestamp


def main():
    if sys.platform != "linux":
        raise RuntimeError("actual Linux host required")
    root = Path(__file__).resolve().parents[1]
    output = root / "docs" / "linux"
    output.mkdir(parents=True, exist_ok=True)
    versions = json.loads((root / "platform" / "versions.json").read_text())
    info = json.loads(command(["docker", "info", "--format", "{{json .}}"]))
    sensor = json.loads(command(["docker", "inspect", "agentguard-tetragon"]))[0]
    signatures = json.loads(Path("/var/lib/agentguard/sensor/image-verification.json").read_text())
    expected_digest = versions["tetragon_image"].split("@", 1)[1]
    signed = any(
        item["critical"]["image"]["docker-manifest-digest"] == expected_digest
        and item["optional"]["Issuer"] == "https://token.actions.githubusercontent.com"
        and item["optional"]["Subject"]
        == "https://github.com/cilium/tetragon/.github/workflows/build-images-releases.yml@refs/tags/"
        + versions["tetragon_release"]
        for item in signatures
    )
    result = {
        "observed_at": timestamp(),
        "host_id": "linux-lab-01",
        "kernel": platform.release(),
        "python": platform.python_version(),
        "docker_engine": info["ServerVersion"],
        "docker_cgroup_version": info["CgroupVersion"],
        "docker_security_options": info["SecurityOptions"],
        "python_base": versions["python_base"],
        "tetragon_image": sensor["Config"]["Image"],
        "tetragon_signature_verified": signed,
        "tetragon_running": sensor["State"]["Running"],
        "tetragon_network_mode": sensor["HostConfig"]["NetworkMode"],
        "tetragon_health": command(["docker", "exec", "agentguard-tetragon", "tetra", "status"]),
        "lab_image": json.loads(command(["docker", "image", "inspect", "agentguard-capsule:lab"]))[
            0
        ]["Id"],
        "socket_lab_image": json.loads(
            command(["docker", "image", "inspect", "agentguard-socket-lab:round1"])
        )[0]["Id"],
        "finance_image": json.loads(
            command(["docker", "image", "inspect", "agentguard-finance:round2"])
        )[0]["Id"],
        "ollama_release_archive_sha256": versions["ollama_archive_sha256"],
        "full_protected_mvp_complete": False,
    }
    try:
        result["supplemental_probe_image"] = {
            "image_id": json.loads(
                command(["docker", "image", "inspect", "agentguard-probes:delivery"])
            )[0]["Id"],
            "scope": "Synthetic curl/scope/baseline lab only; advisory findings require triage before any promotion",
            "dependency_review": "docs/linux/probe_dependency_review.json",
        }
    except (ValueError, RuntimeError):
        result["supplemental_probe_image"] = {"status": "unavailable_or_unverified"}
    try:
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as client:
            version = client.get("http://127.0.0.1:11434/api/version")
            version.raise_for_status()
            models = client.get("http://127.0.0.1:11434/api/tags")
            models.raise_for_status()
        result["model_runtime"] = {
            "version": version.json()["version"],
            "models": [
                {key: model[key] for key in ("name", "digest", "size")}
                for model in models.json()["models"]
                if model["name"] == "qwen2.5:7b"
            ],
        }
    except (httpx.HTTPError, ValueError, KeyError):
        result["model_runtime"] = {"status": "unavailable_or_unverified"}
    audit = host_audit()
    audit["host"] = "linux-lab-01"
    (output / "host_capabilities.json").write_text(json.dumps(audit, indent=2) + "\n")
    (output / "version_manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    audit_path = root / "var" / "linux_dependency_audit.json"
    if audit_path.exists():
        audit = json.loads(audit_path.read_text())
        summary = {
            "dependencies_checked": len(audit["dependencies"]),
            "known_vulnerabilities": sum(len(item["vulns"]) for item in audit["dependencies"]),
            "scope": "locked Python packages; no application data transmitted",
        }
        (output / "dependency_audit.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
