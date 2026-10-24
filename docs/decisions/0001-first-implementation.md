# ADR 0001: executable local core, separate Linux validation gate

Status: initial implementation decision, pending team review.

The starting workspace was empty. The authoring session ran Windows 11 with Python 3.14.2 and no Docker executable on PATH. Initial sandboxed WSL queries returned E_ACCESSDENIED. A later approved read-only query found Ubuntu WSL2; starting it revealed kernel 6.18.33.2, Python 3.14.4, cgroup v2 and BTF, but no Docker CLI. The regression suite also passed there, including the real Unix peer-credential rejection test. Container and eBPF validation are still pending.

We implement a standard-library Python application using the Linux handoff's shared v1 interfaces. This gives both intended team members one contract and event vocabulary. The supplied presentation document's six-slide authoring constraints do not apply to the user's request to build software. The missing Member 1 companion guide is not treated as an implemented service.

We separate a policy harness (trusted local broker tests) from the real Linux isolation lab. The application `/launch` endpoint refuses protected execution until sensor coverage and broker/runtime integration are validated. There is no simulated-success fallback. The harness is explicitly named in routes, state and UI.

The initial control plane trusts one local project owner, authenticated with a random local bearer key. HMAC integrity protects against untrusted workload tampering, not a host administrator. A production multi-user authority will need distinct signing/verification keys, organization policy, identity, revocation and audit of approvals.

The Model Broker has a bounded callable interface but no provider, price model or paid API integration. Requests fail if no provider is configured. A deterministic fake model is not presented as a real AI agent.

The runtime baseline targets a local rootful Linux Docker Engine with cgroup v2 and seccomp. Rootless/userns support remains fail-closed until peer credential mapping can be tested. This does not assert rootful Docker is preferable for all deployments; it narrows the initial verified identity model.

Consequences: the first deliverable is useful and testable on Windows, while its OS-level security claims remain pending real Linux evidence. No architectural novelty or experimental efficacy is claimed.
