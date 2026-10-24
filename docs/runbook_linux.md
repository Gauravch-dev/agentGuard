# Linux runbook

## Current Windows workflow

From the project directory:

```powershell
python -m unittest discover -s tests -v
python -m agentguard demo
python -m agentguard serve
```

Open `http://127.0.0.1:8765` and paste the printed local access key. A server may already be running from the initial build. Stop a foreground server with Ctrl+C. Data persists under `.agentguard/`; the key is never sent to an external service. Do not expose the development server beyond loopback.

The workbench seeds FIN-001 with a one-hour synthetic contract. Restarting `serve` or running `demo` after expiry creates the next immutable version. Brokers always reload and verify their bound version, so expiry is not extended by editing an in-memory object.

## Prepare an owned Linux lab

An Ubuntu WSL2 distribution is already installed on this machine. Its cgroup v2 and BTF paths are present, and the application/Unix peer tests passed there. Docker is absent, so this is a candidate lab host rather than a validated runtime. You can inspect it from PowerShell with `wsl --distribution Ubuntu`; no additional WSL installation is required for the current environment.

Use a dedicated Linux host/VM with a locally accessible Docker Engine. Follow your OS and Docker vendor installation instructions. Privileged host setup must be reviewed by the Linux owner; do not give an agent Docker control, sensor capabilities or host mounts.

```sh
python -m agentguard audit --output platform/docs/host_capabilities.json
python -m unittest discover -s tests -v
docker info
test -f /sys/fs/cgroup/cgroup.controllers
test -f /sys/kernel/btf/vmlinux
```

Record distribution, kernel, architecture, Docker version/security options, cgroup version, BTF, AppArmor/SELinux, namespace tests, time synchronization, RAM/disk and virtualization specifics. The audit is intentionally not a blanket security certification. Rootless/userns and remote daemon contexts are refused by the initial lab adapter.

## Build and run fixed isolation probes

Select a maintained Python base from the official registry; review its version/licenses and record its digest. The Dockerfile requires an explicit immutable base. Replace the placeholder below; it is not a runnable fake digest.

```sh
docker build --build-arg PYTHON_BASE=python@sha256:<verified-digest> -t agentguard-capsule:lab -f platform/profiles/Dockerfile .
python -m agentguard isolation-lab --image agentguard-capsule:lab
```

The launcher resolves that local tag to its immutable ID, creates but does not start the container, verifies the effective profile, rechecks expiry, starts the fixed probes, captures host PID→cgroup mapping, waits with a deadline, checks actual probe outcomes, confirms no populated descendant cgroup and then removes the container. No automatic image pull occurs.

Results are written to `.agentguard/lab-results/`. If containment cannot be confirmed, the adapter attempts a runtime kill, preserves the container for inspect and raises Unverified. A trusted administrator should inspect its recorded ID and captured cgroup; do not assume a kill request proves exit. Avoid deleting unrelated containers or cgroups.

The lab's current fixed probes cover local arithmetic, UID/GID, no-new-privileges, seccomp activation, effective capabilities, loopback-only networking, root filesystem write denial, private root home, absent Docker socket, Python direct-IP and subprocess direct-IP denial. They do not yet cover all DNS/curl/UDP bypasses, credentials, resource exhaustion, cross-capsule attacks or live host observations. The polling deadline is not crash-resilient: a service watchdog is required before arbitrary agent execution.

## Tetragon and socket integration

See `sensors/tetragon/README.md`. Install sensors only outside capsules. Record actual metrics and policy hook semantics; do not turn log recency into proof of healthy collection. Obtain live process/file/connect fixtures from the exact pinned version. The normalizer currently accepts process events only and must receive a trusted lifecycle map.

`transport.CapsuleSocket` is a Linux integration building block, not an enabled runtime endpoint. Create a fresh directory under a protected host parent for each capsule; mount only that directory at a fixed broker path. Test mapped UID and SO_PEERCRED host PID/cgroup against real children. Never treat a request's `task_id` or an in-capsule token as task authority. Revoke before cleanup; verify socket removal and cgroup exit.

## Debugging and rollback

- Preflight refuses: inspect the structured reasons; do not remove restrictions to make a run pass.
- Model request denies: no provider is configured. Do not place credentials in the capsule.
- Output holds: check required coverage, trusted context, expiry, schema and recomputed aggregates.
- Journal integrity fails: preserve state and mark Unverified. Do not rewrite signatures or delete events to clear the alert.
- Stop the workbench with Ctrl+C; no system-wide services were installed. Back up `.agentguard/` with its authority key as sensitive local state. No automatic deletion/retention job is configured.

## References checked while authoring

- [Docker network none](https://docs.docker.com/engine/network/drivers/none/)
- [Docker seccomp](https://docs.docker.com/engine/security/seccomp/)
- [Docker resource controls](https://docs.docker.com/engine/containers/resource_constraints/)
- [Tetragon container deployment](https://tetragon.io/docs/installation/container/)
- [Tetragon API](https://tetragon.io/docs/reference/grpc-api/)
- [Tetragon health/loss/export metrics](https://tetragon.io/docs/reference/metrics/)
