"""Synthetic negative probes, invoked explicitly by the trusted Linux lab only.

No Finance code, secrets, confidential data, external server or provider is used.
The approved runtime retains network=none and all its ordinary restrictions.
"""

import ctypes
import errno
import json
import mmap
import os
import shutil
import socket
import subprocess
import sys
import time

results = {}
# Separate synthetic paths let the host verify inherited-FD/readv/mmap hooks
# against the actual operation, rather than counting unrelated Python startup I/O.
for canary in ("inherited", "readv", "mmap"):
    with open("/work/probe-" + canary, "wb") as seed:
        seed.write(b"agentguard-synthetic-scope-canary-0123456789")


def attempt(name, operation):
    start = time.monotonic_ns()
    try:
        results[name] = {"outcome": "completed", "value": operation()}
    except OSError as exc:
        results[name] = {"outcome": "refused", "errno": exc.errno}
    finally:
        results[name]["elapsed_ns"] = time.monotonic_ns() - start


def read_allowed():
    with open("/etc/os-release", "rb") as stream:
        return len(stream.read(32))


def read_forbidden():
    with open("/etc/shadow", "rb") as stream:
        return len(stream.read(1))


def write_forbidden():
    with open("/etc/agentguard-synthetic-write", "wb") as stream:
        return stream.write(b"synthetic")


def inherited_read():
    descriptor = os.open("/work/probe-inherited", os.O_RDONLY)
    try:
        child = subprocess.run(
            [sys.executable, "-I", "-c", f"import os; print(len(os.read({descriptor},32)))"],
            pass_fds=(descriptor,), capture_output=True, text=True, timeout=3, check=True,
        )
        return int(child.stdout)
    finally:
        os.close(descriptor)


def vector_read():
    descriptor = os.open("/work/probe-readv", os.O_RDONLY)
    try:
        return os.readv(descriptor, [bytearray(16), bytearray(16)])
    finally:
        os.close(descriptor)


def mapped_read():
    with open("/work/probe-mmap", "rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapping:
        return len(mapping[:1])


def uring_setup():
    # x86_64 reviewed syscall number; never submit asynchronous I/O. If setup
    # succeeds, immediately close the ring and report that unexpected capability.
    if os.uname().machine != "x86_64":
        return {"unsupported_architecture": True}
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    params = ctypes.create_string_buffer(256)
    descriptor = library.syscall(425, 1, ctypes.byref(params))
    if descriptor == -1:
        number = ctypes.get_errno()
        raise OSError(number, errno.errorcode.get(number, "kernel refusal"))
    os.close(descriptor)
    return {"ring_created": True, "io_submitted": False}


def network(family, kind, target):
    with socket.socket(family, kind) as stream:
        stream.settimeout(0.3)
        if kind == socket.SOCK_STREAM:
            stream.connect(target)
            return 0
        return stream.sendto(b"agentguard-synthetic", target)


def inherited_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.connect(("127.0.0.1", 49221))
        descriptor = stream.fileno()
        child = subprocess.run(
            [sys.executable, "-I", "-c", f"import socket; s=socket.socket(fileno={descriptor}); print(s.send(b'agentguard-synthetic'))"],
            pass_fds=(descriptor,), capture_output=True, text=True, timeout=3, check=True,
        )
        return int(child.stdout)


attempt("allowed_open_read", read_allowed)
attempt("forbidden_shadow_read", read_forbidden)
attempt("readonly_root_write", write_forbidden)
attempt("inherited_descriptor_read", inherited_read)
attempt("readv", vector_read)
attempt("file_mmap", mapped_read)
attempt("io_uring_setup", uring_setup)
attempt("tcp_ipv4", lambda: network(socket.AF_INET, socket.SOCK_STREAM, ("192.0.2.1", 443)))
attempt("udp_dns", lambda: network(socket.AF_INET, socket.SOCK_DGRAM, ("192.0.2.53", 53)))
attempt("udp_ipv6", lambda: network(socket.AF_INET6, socket.SOCK_DGRAM, ("2001:db8::1", 53)))
attempt("raw_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close())
attempt("dns_name", lambda: len(socket.getaddrinfo("agentguard.invalid", 443)))
attempt("inherited_socket_loopback", inherited_socket)
child = subprocess.run([sys.executable, "-I", "-c", "import socket; s=socket.socket(); s.settimeout(.3); s.connect(('192.0.2.2',443))"], capture_output=True, timeout=3)
results["child_python_egress"] = {"exit_code": child.returncode}
curl = shutil.which("curl")
if curl:
    start = time.monotonic_ns()
    child = subprocess.run([curl, "--noproxy", "*", "--connect-timeout", "1", "--max-time", "2", "--silent", "--output", "/dev/null", "https://192.0.2.1/"], capture_output=True, timeout=3)
    results["child_curl_egress"] = {"outcome": "executed", "exit_code": child.returncode, "elapsed_ns": time.monotonic_ns() - start}
else:
    results["child_curl_egress"] = {"outcome": "unsupported", "reason": "curl absent from this immutable image"}
print(json.dumps(results))
