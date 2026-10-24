# AgentGuard 2.0

Task-scoped permissions, restricted Linux execution, and independent verification for AI agents.

This is the first implementation of the supplied proposal. It includes a working local policy/evidence workbench and a real Docker isolation-lab adapter. **It is not yet a validated agent security product.** Protected agent execution stays disabled until live sensor coverage and the broker/container integration pass the Linux acceptance gates.

## Run on Windows, Linux or macOS

Python 3.11+; no third-party Python dependencies.

```powershell
python -m agentguard audit --output platform/docs/host_capabilities.json
python -m unittest discover -s tests -v
python -m agentguard demo
python -m agentguard serve
```

`serve` binds only to `127.0.0.1:8765`. Open that address and paste the local access key printed by the command. The dashboard can run a **policy harness**, inspect contracts, broker denials and findings. Harness execution runs trusted test code locally, never arbitrary agent code, and always reports unavailable independent OS coverage. It does not pretend to be a TaskCapsule.

State defaults to `.agentguard/`: local authority key, SQLite contracts, append-only evidence with an HMAC chain, reports and a local UI access key. Keep that directory outside any untrusted capsule. SQLite/HMAC protects against accidental changes and agent-level tampering; a trusted host administrator can replace both the database and key. Local encryption at rest is not implemented.

## What is implemented

- Strict version 1 task/event validation; immutable authority-approved contracts with integrity signatures and expiry checks.
- Aggregate-only synthetic Data Broker; strict structured Output Broker; bounded Model Broker interface (no model provider configured by default).
- Separate business outcomes and concurrent Aligned / Blocked / Unexplained / Unverified findings; evidence source, receipt time and raw reference preservation.
- Local SQLite evidence journal with source-scoped deduplication and integrity verification.
- Docker command builder, mandatory preflight, effective configuration inspection, lifecycle deadlines and cgroup termination verification for the Linux isolation lab.
- Per-capsule Unix socket transport with Linux peer-credential/cgroup checks; Tetragon process-event normalizer and source identity mapping.
- Authenticated local API and investigation dashboard, synthetic test harness and automated security regression tests.

See [integration status](docs/integration_status.md), [Linux runbook](docs/runbook_linux.md), [threat model](docs/threat_model.md), and [acceptance matrix](docs/experiment_results.md). Their validation limits are part of the implementation.

Validated on Windows (50 tests passed, one Linux-only test skipped) and the installed Ubuntu WSL2 distribution (51 passed). WSL has cgroup v2 and BTF, but Docker is not installed; no real container or live sensor security result is claimed.

## Linux isolation lab

On an owned, dedicated Linux host with local Docker Engine, cgroup v2 and seccomp:

```sh
# Choose and verify an approved immutable Python base image first.
docker build --build-arg PYTHON_BASE=python@sha256:<verified-digest> -t agentguard-capsule:lab -f platform/profiles/Dockerfile .
python -m agentguard isolation-lab --image agentguard-capsule:lab
```

The adapter resolves the local tag to an immutable image ID, never pulls implicitly, accepts no arbitrary Docker flags, and runs only the image's fixed lab entrypoint. It verifies restrictions before starting, checks active controls from inside the container, tests denied direct/child networking and writes a local calculation. The lab has no protected company data, model credentials or broker socket. **Passing this lab is not passing the full S01–S16 MVP.**

## Project layout

`agentguard/` implements the application, shared schemas, platform adapter and collector interfaces. `contracts/` contains machine-readable JSON schemas. `platform/` contains the image and host reports. `sensors/` documents the Tetragon integration. `dashboard/` contains the local investigation UI. `tests/` and `docs/` hold verification and handoff material.

The two source documents were treated as requirements/context. Their presentation-authoring instructions do not request a slide deck; their member ownership boundaries describe an intended team, not evidence of existing code. The versioned shared interface in the Linux handoff takes precedence over the presentation's illustrative contract.
