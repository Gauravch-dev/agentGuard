"""Reviewed observation-only syscall hooks scoped to one captured mount namespace.

These hooks prove only their stated syscall scope, not every possible file or
network operation. They collect names/addresses and return codes, never payloads.
"""

import hashlib
import ipaddress
import re

from agentguard.schema import canonical, event
from agentguard.sensors import MappingError
from agentguard.source_time import ordered_times

# No buffers/payloads are captured. Permission hooks prove a permission check,
# never bytes read or a completed mmap. Actual read/write returns prove only
# the stated VFS operation, including use of an inherited descriptor.
FILE_IO = {"vfs_read", "vfs_write", "vfs_readv", "vfs_writev", "vfs_iter_read", "vfs_iter_write"}
FILE_CHECKS = {"security_file_permission", "security_mmap_file"}
SOCKET_IO = {"sock_sendmsg", "sock_recvmsg", "udp_sendmsg", "udpv6_sendmsg", "tcp_sendmsg"}


def capsule_policy(name: str, mount_namespace: int, *, expanded=False) -> dict:
    if not re.fullmatch(r"agentguard-[a-f0-9]{32}", name):
        raise ValueError("Invalid managed policy name")
    if type(mount_namespace) is not int or mount_namespace < 1:
        raise ValueError("Captured mount namespace inode required")
    hooks = []
    definitions = [
        ("sys_openat", [{"index": 1, "type": "string"}]),
        ("sys_openat2", [{"index": 1, "type": "string"}]),
        ("sys_connect", [{"index": 1, "type": "sockaddr"}]),
        ("sys_sendto", [{"index": 4, "type": "sockaddr"}]),
        ("sys_sendmsg", []),
        ("sys_sendmmsg", []),
    ]
    if expanded:
        definitions.extend((call, [{"index": 0, "type": "file"}]) for call in sorted(FILE_IO))
        definitions.extend((call, [{"index": 0, "type": "file"}]) for call in sorted(FILE_CHECKS))
        definitions.extend(
            (call, [{"index": 0, "type": "socket" if call.startswith("sock_") else "sock"}])
            for call in sorted(SOCKET_IO)
        )
    for call, args in definitions:
        hooks.append(
            {
                "call": call,
                "syscall": call.startswith("sys_"),
                "return": True,
                "args": args,
                "returnArg": {
                    "index": 0,
                    "type": "int" if call in FILE_CHECKS | SOCKET_IO else "long",
                },
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


def prebirth_policy(name, canary_path, sensor_namespace, observer_namespace):
    """Attach before namespaces exist; source-side persistence filters by container.

    A single exact host openat canary proves this policy's subscription. Other
    host operations are excluded in-kernel. No host canary frame is persisted.
    """
    policy = capsule_policy(name, 1, expanded=True)
    if any(type(value) is not int or value < 1 for value in (sensor_namespace, observer_namespace)):
        raise ValueError("Verified sensor mount namespace required")
    for hook in policy["spec"]["kprobes"]:
        hook["selectors"] = [
            {
                "matchNamespaces": [
                    {
                        "namespace": "Mnt",
                        "operator": "NotIn",
                        "values": sorted(
                            {"host_ns", str(sensor_namespace), str(observer_namespace)}
                        ),
                    }
                ]
            }
        ]
        if hook["call"] == "sys_openat":
            hook["selectors"].append(
                {
                    "matchArgs": [{"index": 1, "operator": "Equal", "values": [str(canary_path)]}],
                }
            )
    return policy


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
            hook["call"]
            for hook in capsule_policy("agentguard-" + "0" * 32, 1, expanded=True)["spec"][
                "kprobes"
            ]
        }:
            raise MappingError("Unsupported kernel hook")
        process = body.get("process", {})
        docker, start, observed = process.get("docker"), process.get("start_time"), raw.get("time")
        if not isinstance(docker, str) or len(docker) < 12 or not start or not observed:
            raise MappingError("Missing source process/container identity")
        matches = [
            w
            for w in self.workloads
            if w.container_id.startswith(docker)
            and ordered_times(w.started_at, start, observed, w.ended_at)
        ]
        if len(matches) != 1:
            raise MappingError("Ambiguous, expired or unknown hook workload")
        workload = matches[0]
        pid = process.get("pid")
        if type(pid) is not int or pid <= 0:
            raise MappingError("Missing source process PID")
        if syscall in FILE_CHECKS | SOCKET_IO:
            result = body.get("return", {}).get("int_arg")
            if type(result) is not int or not -(2**31) <= result < 2**31:
                raise MappingError("Missing signed kernel int return value")
        else:
            returned = body.get("return", {}).get("long_arg")
            if not isinstance(returned, str) or not re.fullmatch(r"-?[0-9]{1,19}", returned):
                raise MappingError("Missing syscall return value")
            result = int(returned)
            if not -(2**63) <= result < 2**63:
                raise MappingError("Invalid signed kernel long return value")
        args = body.get("args", [])
        resource = None
        is_file = syscall in {"sys_openat", "sys_openat2"} | FILE_IO | FILE_CHECKS
        if syscall in {"sys_openat", "sys_openat2"}:
            if len(args) != 1 or not isinstance(args[0].get("string_arg"), str):
                raise MappingError("Missing source filename")
            resource = args[0]["string_arg"]
        elif syscall in FILE_IO | FILE_CHECKS:
            if len(args) != 1 or not isinstance(args[0].get("file_arg"), dict):
                raise MappingError("Missing source file identity")
            resource = args[0]["file_arg"].get("path")
            if not isinstance(resource, str) or not resource.startswith("/"):
                raise MappingError("Unresolved source file path")
        elif syscall in SOCKET_IO:
            if len(args) != 1 or not isinstance(args[0].get("sock_arg"), dict):
                raise MappingError("Missing socket metadata")
            address = args[0]["sock_arg"]
            if address.get("family") not in {"AF_INET", "AF_INET6"}:
                raise MappingError("Non-IP socket operation; no IP flow inferred")
            ip = ipaddress.ip_address(address["daddr"])
            if ip.version != (4 if address["family"] == "AF_INET" else 6):
                raise MappingError("Socket family/address mismatch")
            port = address.get("dport", 0)
            if type(port) is not int or not 0 <= port <= 65535:
                raise MappingError("Invalid socket port")
            resource = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
            if ip.is_unspecified or port == 0:
                # An unconnected socket snapshot does not identify the sendto
                # destination carried in the separate message argument.
                resource = None
        elif syscall in {"sys_connect", "sys_sendto"}:
            if len(args) != 1 or not isinstance(args[0].get("sockaddr_arg"), dict):
                raise MappingError("Missing source socket address")
            address = args[0]["sockaddr_arg"]
            if address.get("family") not in {"AF_INET", "AF_INET6"}:
                # Unix broker traffic is not an IP egress attempt.
                raise MappingError("Unsupported non-IP address; retain source record")
            ip = ipaddress.ip_address(address["addr"])
            if ip.version != (4 if address["family"] == "AF_INET" else 6):
                raise MappingError("Syscall socket family/address mismatch")
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
            effect=hook_effect(syscall.removeprefix("sys_"), result),
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


def hook_effect(operation, returned):
    # Permission checks and zero-byte I/O do not prove a data effect. A positive
    # socket send proves accepted bytes at that hook, not delivery of a packet.
    if operation in FILE_CHECKS or returned < 0:
        return "attempted"
    if operation in FILE_IO | SOCKET_IO and returned == 0:
        return "attempted"
    return "observed"
