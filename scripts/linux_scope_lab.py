"""Real expanded-hook acceptance probes, with explicit supported/unknown scope.

Trusted docker-exec probes supplement the held Finance workload. They are not an
admitted agent or complete-coverage result. No source events are manufactured.
"""

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from agentguard.capsules import StagedCapsules, private_directory
from agentguard.hook_policy import HookNormalizer, capsule_policy
from agentguard.platform import command
from agentguard.policy_control import install_policy, remove_policy
from agentguard.schema import strict_json, timestamp
from agentguard.sensors import Workload
from agentguard.supervisor import verified_mount_namespace
from application.authority import Authority
from application.member2_bridge import translate_member2_event
from application.store import Store

ROOT = Path(__file__).resolve().parents[1]


def run(image, output):
    os.umask(0o077)
    private = private_directory(Path("/var/lib/agentguard/scope-lab") / uuid4().hex)
    store = Store(private / "evidence.sqlite3", os.urandom(32).hex())
    controller = StagedCapsules(image, state_root=private / "runtime")
    contract = Authority(store).create("linux-lab-owner")
    value = controller.prepare(contract.model_dump(mode="json"))
    policy_name = "agentguard-" + uuid4().hex
    loaded, subscription = False, None
    try:
        policy = capsule_policy(policy_name, verified_mount_namespace(value), expanded=True)
        path = private / "policy.json"
        path.write_text(json.dumps(policy))
        loaded = True
        install_policy(path, policy_name)
        capture = private / "hooks.jsonl"
        with capture.open("xb") as raw, (private / "source.stderr").open("xb") as errors:
            subscription = subprocess.Popen(  # noqa: S603 - fixed managed source
                [
                    "/usr/bin/docker",
                    "exec",
                    "agentguard-tetragon",
                    "timeout",
                    "-s",
                    "TERM",
                    "-k",
                    "2",
                    "55",
                    "tetra",
                    "getevents",
                    "--policy-names",
                    policy_name,
                    "--exclude-fields",
                    "process.arguments,parent.arguments",
                ],
                stdin=subprocess.DEVNULL,
                stdout=raw,
                stderr=errors,
                start_new_session=True,
            )
            # This delay is not a subscription attestation. The result records
            # only actual captured frames and retains missing evidence as gaps.
            time.sleep(0.5)
            if subscription.poll() is not None:
                raise RuntimeError("Actual scoped source exited")
            probe = (ROOT / "platform/profiles/scope_probe.py").read_text()
            probes = json.loads(
                command(
                    [
                        "docker",
                        "exec",
                        "--user=65532:65532",
                        value["container_id"],
                        "python",
                        "-I",
                        "-c",
                        probe,
                    ],
                    timeout=20,
                )
            )
            subscription.wait(timeout=60)
        workload = Workload(
            value["container_id"],
            "cg-" + str(value["identity"]["cgroup_inode"]),
            value["task_id"],
            value["contract_version"],
            value["capsule_id"],
            "linux-lab-01",
            value["identity"]["process_start_observed_at"],
        )
        normalizer = HookNormalizer("linux-hooks-01", [workload], [policy_name])
        counts, normalized, gaps, binaries = {}, [], {}, {}
        for line in capture.read_bytes().splitlines():
            raw = strict_json(line)
            body = raw.get("process_kprobe", {})
            source = body.get("process", {})
            docker = source.get("docker", "")
            if (
                not isinstance(docker, str)
                or len(docker) < 12
                or not value["container_id"].startswith(docker)
            ):
                gaps["unattributed_or_foreign_source"] = (
                    gaps.get("unattributed_or_foreign_source", 0) + 1
                )
                continue
            function = body.get("function_name", "unknown")
            counts[function] = counts.get(function, 0) + 1
            binary = source.get("binary", "unknown")
            binaries.setdefault(binary, {})[function] = (
                binaries.get(binary, {}).get(function, 0) + 1
            )
            try:
                reference = "tetragon:" + hashlib.sha256(line).hexdigest()
                event, metadata = translate_member2_event(
                    normalizer.normalize(raw, reference), "linux-hooks-01"
                )
                normalized.append((event, metadata))
            except (ValueError, PermissionError, KeyError) as exc:
                # Bounded codes, not raw paths/arguments from private diagnostics.
                code = type(exc).__name__
                gaps[code] = gaps.get(code, 0) + 1
        supported = {
            name: {
                "captured": counts.get(name, 0),
                "normalized": sum(
                    metadata["details"]["kernel_return"] >= -(2**63)
                    and event.operation == name.removeprefix("__x64_sys_").removeprefix("sys_")
                    for event, metadata in normalized
                ),
            }
            for name in sorted(counts)
        }
        cleanup = controller.terminate(value["capsule_id"])
        checks = {
            "restricted_file_read_refused": probes["forbidden_shadow_read"]["outcome"] == "refused",
            "readonly_root_write_refused": probes["readonly_root_write"]["outcome"] == "refused",
            "inherited_fd_read_executed": probes["inherited_descriptor_read"].get("value") == 32,
            "readv_executed": probes["readv"].get("value") == 32,
            "file_mmap_executed": probes["file_mmap"].get("value") == 1,
            "inherited_fd_actual_path_and_read_observed": any(
                event.operation == "vfs_read"
                and event.resource_or_destination == "/work/probe-inherited"
                and metadata["details"]["kernel_return"] == 32
                for event, metadata in normalized
            ),
            "readv_actual_path_and_read_observed": any(
                event.operation == "vfs_readv"
                and event.resource_or_destination == "/work/probe-readv"
                and metadata["details"]["kernel_return"] == 32
                for event, metadata in normalized
            ),
            "mmap_permission_on_actual_probe_path_observed": any(
                event.operation == "security_mmap_file"
                and event.resource_or_destination == "/work/probe-mmap"
                for event, _ in normalized
            ),
            "direct_and_alternate_protocols_refused": all(
                probes[name]["outcome"] == "refused"
                for name in ("tcp_ipv4", "udp_dns", "udp_ipv6", "raw_socket", "dns_name")
            ),
            "child_python_egress_refused": probes["child_python_egress"]["exit_code"] != 0,
            "child_curl_egress_refused": probes["child_curl_egress"]["outcome"] == "executed"
            and probes["child_curl_egress"]["exit_code"] != 0,
            "actual_curl_connect_hook_captured": any(
                binary.endswith("/curl") and any("connect" in function for function in functions)
                for binary, functions in binaries.items()
            ),
            "actual_file_and_socket_hooks_observed": {
                "vfs_read",
                "security_mmap_file",
                "udp_sendmsg",
            }
            <= counts.keys(),
            "permission_check_never_claims_completed_read": all(
                event.effect_status == "attempted"
                for event, _ in normalized
                if event.operation.startswith("security_")
            ),
            "finance_not_admitted": not cleanup["admitted"],
            "cleanup_verified": cleanup["descendants_exited"] and cleanup["channel_revoked"],
        }
        result = {
            "observed_at": timestamp(),
            "mode": "real-linux-expanded-scope-lab",
            "image_id": image,
            "capsule_id": value["capsule_id"],
            "checks": checks,
            "passed": all(checks.values()),
            "probe_results": probes,
            "hook_matrix": supported,
            "hooks_by_binary": binaries,
            "normalization_gaps": gaps,
            "event_samples": [event.model_dump(mode="json") for event, _ in normalized[:12]],
            "source_reference": "operator-retained-scope:" + private.name,
            "coverage_status": "partial",
            "protected_execution_ready": False,
            "limits": [
                "Trusted negative probes, not admitted Finance execution",
                "mmap permission observation does not prove each page read",
                "io_uring refusal is not independent syscall observation",
                "Socket send is not packet delivery or packet-to-process attribution",
                "No initial subscription or lossless coverage claim",
            ],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result
    finally:
        if subscription is not None and subscription.poll() is None:
            subscription.terminate()
            subscription.wait(timeout=5)
        controller.terminate(value["capsule_id"])
        if loaded:
            remove_policy(policy_name)
        store.db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, default=Path("docs/linux/scope_review.json"))
    args = parser.parse_args()
    result = run(args.image_id, args.output)
    print(
        json.dumps(
            {
                "passed": result["passed"],
                "checks": result["checks"],
                "hook_matrix": result["hook_matrix"],
            },
            indent=2,
        )
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
