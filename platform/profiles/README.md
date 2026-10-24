The Docker adapter fixes UID/GID 65532, all capability drops, no-new-privileges, Docker's default seccomp, read-only root, private namespaces, no network, two bounded tmpfs mounts, CPU/memory/swap/PID/log/FD limits and a fixed lab entrypoint. No agent-supplied host paths or flags are accepted.

The local image is trusted input selected by an administrator and resolved to an immutable image ID before create. Its base must be selected by verified digest. We have not vetted or downloaded a base image in this Windows session. Do not insert an invented digest.

This first lab deliberately rejects rootless/userns configurations until Unix peer identity and cgroup attribution are tested there. Appropriate AppArmor/SELinux profile validation and syscall-level bypass tests remain pending; Docker's default seccomp alone is not a complete sandbox.

Runtime references checked during implementation:

- https://docs.docker.com/engine/network/drivers/none/
- https://docs.docker.com/engine/security/seccomp/
- https://docs.docker.com/engine/containers/resource_constraints/
