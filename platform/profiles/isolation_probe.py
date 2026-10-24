"""Fixed synthetic Linux lab workload, not an AI agent or trusted host sensor."""

import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

# Give the trusted launcher time to capture this workload's cgroup before exit.
time.sleep(2)
checks = {}
checks["unprivileged_uid_gid"] = os.getuid() == 65532 and os.getgid() == 65532
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
checks["no_new_privs"] = status.get("NoNewPrivs", "").strip() == "1"
checks["seccomp_filter"] = status.get("Seccomp", "").strip() == "2"
checks["zero_effective_caps"] = int(status.get("CapEff", "1").strip(), 16) == 0
checks["network_only_loopback"] = set(path.name for path in Path("/sys/class/net").iterdir()) == {"lo"}
checks["no_docker_socket"] = not Path("/var/run/docker.sock").exists()
try:
    checks["root_ssh_unavailable"] = not Path("/root/.ssh/id_rsa").exists()
except PermissionError:
    checks["root_ssh_unavailable"] = True
try:
    # This image directory is mode 777 so a denial tests the read-only mount,
    # rather than merely an unprivileged UID's directory permissions.
    Path("/opt/agentguard-rootfs-canary/forbidden-write").write_text("synthetic")
    checks["root_read_only"] = False
except OSError as exc:
    checks["root_read_only"] = exc.errno == errno.EROFS
try:
    Path("/root").iterdir().__next__()
    checks["root_home_denied"] = False
except PermissionError:
    checks["root_home_denied"] = True
except (StopIteration, FileNotFoundError):
    checks["root_home_denied"] = False
try:
    with socket.create_connection(("192.0.2.1", 443), timeout=1):
        checks["direct_network_denied"] = False
except OSError as exc:
    # Timeout does not prove a network boundary. Require an explicit OS denial.
    checks["direct_network_denied"] = exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM}
child = subprocess.run([sys.executable, "-I", "-c", "import socket,errno,sys\ntry:\n s=socket.create_connection(('192.0.2.1',443),timeout=1);sys.exit(1)\nexcept OSError as e:\n sys.exit(0 if e.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EACCES,errno.EPERM) else 2)"], timeout=3)
checks["child_network_denied"] = child.returncode == 0
Path("/work/local-result.json").write_text(json.dumps({"sum": sum([1, 2, 3])}))
checks["local_calculation"] = json.loads(Path("/work/local-result.json").read_text())["sum"] == 6
print(json.dumps({"passed": all(checks.values()), "checks": checks, "evidence_source": "fixed in-container lab probes; not host sensor telemetry"}), flush=True)
sys.exit(0 if all(checks.values()) else 1)
