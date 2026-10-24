# Host capability report

Observed 24 October 2026 in the managed development session. Machine-readable results: `host_capabilities.json`.

| Feature | Result | Evidence/limit |
|---|---|---|
| OS | Windows 11 / AMD64 | Python platform inventory |
| Python | Supported, 3.14.2 | `python --version` |
| Node | Available, 24.13.0 | `node --version`; dashboard syntax check only |
| Docker CLI | Unsupported in this session | Not on PATH |
| WSL access | Available with approved execution permission | Initial sandbox queries denied; approved query found Ubuntu WSL2 |
| Linux cgroup v2 / BTF | Unavailable on current execution host | Linux paths absent |
| Namespaces/seccomp/AppArmor/SELinux | Untested | Requires actual Linux host/kernel and active probes |
| Tetragon/eBPF/file/connect probes | Untested | No live sensor |
| Sensor drop/export accounting | Untested | No live metrics |
| Clock sync | Untested | No trusted synchronization check |
| Unix peer identity / userns mapping | Peer rejection test passed in WSL; container/userns mapping untested | Linux-only test skipped on Windows, passed under actual WSL Linux |
| Cgroup descendant termination | Untested | No Linux container launched |
| GPU | Not investigated | Optional; not required for isolation correctness |

The installed Ubuntu WSL2 environment was started after the approved query. It reports Python 3.14.4, kernel 6.18.33.2-microsoft-standard-WSL2, cgroup v2 and BTF present, no Docker CLI, no Node, and default UID 0. Machine-readable report: `host_capabilities_wsl.json`. All 51 Python regression tests passed there, including the Unix peer rejection test. Namespace isolation, eBPF probe operation, actual container identity and sensor visibility remain untested; presence of BTF does not prove sensor readiness. No kernel, Docker, WSL or driver installation was attempted.
