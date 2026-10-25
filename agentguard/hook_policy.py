"""Reviewed observation-only syscall hooks scoped to one captured mount namespace.

These hooks prove only their stated syscall scope, not every possible file or
network operation. They collect names/addresses and return codes, never payloads.
"""

import hashlib
import ipaddress
import re

from agentguard.schema import canonical, event, parse_time
from agentguard.sensors import MappingError


def capsule_policy(name: str, mount_namespace: int) -> dict:
    if not re.fullmatch(r"agentguard-[a-f0-9]{32}", name):
        raise ValueError("Invalid managed policy name")
    if type(mount_namespace) is not int or mount_namespace < 1:
        raise ValueError("Captured mount namespace inode required")
    hooks = []
    for call, args in (
        ("sys_openat", [{"index": 1, "type": "string"}]),
        ("sys_openat2", [{"index": 1, "type": "string"}]),
        ("sys_connect", [{"index": 1, "type": "sockaddr"}]),
        ("sys_sendto", [{"index": 4, "type": "sockaddr"}]),
        ("sys_sendmsg", []),
        ("sys_sendmmsg", []),
    ):
        hooks.append(
            {
                "call": call,
                "syscall": True,
                "return": True,
                "args": args,
                "returnArg": {"index": 0, "type": "long"},
                "selectors": [
                    {
                        "matchNamespaces": [
                            {
                                "namespace": "Mnt",
                                "operator": "In",
                                "values": [str(mount_namespace)],
                            }
                        ]
                    }
                ],
            }
        )
    return {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {"name": name},
        "spec": {"kprobes": hooks},
    }


class HookNormalizer:
    def __init__(self, sensor_id, workloads, policy_names):
        self.sensor_id, self.workloads = sensor_id, list(workloads)
        self.policy_names = set(policy_names)

    def normalize(self, raw, reference):
        body = raw.get("process_kprobe", {})
        if not isinstance(body, dict) or body.get("policy_name") not in self.policy_names:
            raise MappingError("Unknown observation policy")
        function = body.get("function_name", "")
        syscall = function.removeprefix("__x64_")
        if syscall not in {
            hook["call"] for hook in capsule_policy("agentguard-" + "0" * 32, 1)["spec"]["kprobes"]
        }:
            raise MappingError("Unsupported kernel hook")
        process = body.get("process", {})
        docker, start, observed = process.get("docker"), process.get("start_time"), raw.get("time")
        if not isinstance(docker, str) or len(docker) < 12 or not start or not observed:
            raise MappingError("Missing source process/container identity")
        start_time, observed_time = parse_time(start), parse_time(observed)
        matches = [
            w
            for w in self.workloads
            if w.container_id.startswith(docker)
            and parse_time(w.started_at) <= start_time <= observed_time
            and (w.ended_at is None or observed_time <= parse_time(w.ended_at))
        ]
        if len(matches) != 1:
            raise MappingError("Ambiguous, expired or unknown hook workload")
        workload = matches[0]
        pid = process.get("pid")
        if type(pid) is not int or pid <= 0:
            raise MappingError("Missing source process PID")
        returned = body.get("return", {}).get("long_arg")
        if not isinstance(returned, str) or not re.fullmatch(r"-?[0-9]{1,19}", returned):
            raise MappingError("Missing syscall return value")
        result = int(returned)
        args = body.get("args", [])
        resource = None
        is_file = syscall in {"sys_openat", "sys_openat2"}
        if is_file:
            if len(args) != 1 or not isinstance(args[0].get("string_arg"), str):
                raise MappingError("Missing source filename")
            resource = args[0]["string_arg"]
        elif syscall in {"sys_connect", "sys_sendto"}:
            if len(args) != 1 or not isinstance(args[0].get("sockaddr_arg"), dict):
                raise MappingError("Missing source socket address")
            address = args[0]["sockaddr_arg"]
            if address.get("family") not in {"AF_INET", "AF_INET6"}:
                # Unix broker traffic is not an IP egress attempt.
                raise MappingError("Unsupported non-IP address; retain source record")
            ip = ipaddress.ip_address(address["addr"])
            port = address.get("port")
            if type(port) is not int or not 0 <= port <= 65535:
                raise MappingError("Invalid source port")
            resource = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
        identity = hashlib.sha256((self.sensor_id + "\0" + canonical(raw)).encode()).hexdigest()
        return event(
            task_id=workload.task_id,
            contract_version=workload.contract_version,
            capsule_id=workload.capsule_id,
            host_id=workload.host_id,
            source="host_sensor",
            event_type="file_access" if is_file else "connection_attempt",
            operation=syscall.removeprefix("sys_"),
            resource=resource,
            verdict="unknown",
            effect="attempted" if result < 0 else "observed",
            coverage="partial",
            event_id=identity,
            observed_at=observed,
            process_identity={"pid": pid, "start_time": start, "cgroup_id": workload.cgroup_id},
            evidence_reference=reference,
            details={
                "sensor_id": self.sensor_id,
                "coverage_scope": "listed syscall and return only",
                "attribution_basis": "trusted lifecycle map + source container + process start",
                "hook_policy": body["policy_name"],
                "kernel_return": result,
            },
        )
