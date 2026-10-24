# AgentGuard 2.0 — integrated application and Linux platform work

## Latest Linux implementation round

The Linux platform now has reproducible Docker/Tetragon setup, pinned images, a
host-admitted staged launcher, private broker socket mounts and a detached durable
deadline watchdog. Real Linux experiments verify peer/cgroup denial, raw-row output
blocking, channel revocation, child cleanup and genuine Tetragon process observations.

**Full protected AI execution remains disabled.** Process-only visibility, sampled
metrics and a passing socket lab do not establish all required sensor coverage.
One recorded source timestamp conflict is retained as an attribution gap. File/
connection hooks, continuous loss accounting, network flows, protected application
admission and the real local model round are still open.

See [the Linux handoff results](docs/linux_handoff_results.md),
[actual versions](docs/linux/version_manifest.json), and
[real socket/containment evidence](docs/linux/socket_lab.json).
The integrated application can now be started on the Linux host with
`python -m scripts.start_linux`; host-only credentials persist in a private directory.

## Application integration checkpoint

This integration builds on Member 2's repository, commit
`198aea6515954130ed58ed21601a23be767596a0`. It adds the Member 1 FastAPI/React application and
explicit integration bridges. The earlier Member 1 workspace is preserved.

**Protected AI execution is still disabled.** Member 2's preflight refuses it until
live sensors, the protected launcher and cross-capsule socket tests are ready.
The prior application checkpoint used a Windows host without WSL or Docker. Its
historical validation did not claim live Linux/model results; the newer Linux
experiments are linked above. Dependency/advisory queries transfer no application data.

## Run the integrated application

After the setup below, start the local application from this repository:

```powershell
.\scripts\start-local.ps1
```

Open http://127.0.0.1:8000 and paste the generated local owner token. The dashboard
shows real platform capability/preflight results, contracts, events, findings and
reports. Creating a task works; protected launch correctly refuses on this host.
The script uses a fresh synthetic database and ephemeral keys for each session.

For a fresh checkout, use Python 3.12+, uv, Node 22.12+ and npm:

```powershell
uv sync --locked
cd dashboard/application
npm ci --ignore-scripts
npm run build
cd ../..
.\scripts\start-local.ps1
```

## What was joined

- Member 1 Task Authority, aggregate/model/output brokers, Finance Agent, evidence
  ledger, deterministic TERE and React dashboard.
- Member 2's actual Docker preflight and fixed isolation lab, exposed through the
  application. A passing lab never enables protected agent execution.
- Member 2's Tetragon normalizer feeding an authenticated application endpoint.
  Collector metadata is preserved separately; the original shared event is unchanged.
- Member 2's peer authorizer used by the application socket transport, with process
  birth, cgroup inode and current contract/channel checks. Real two-container tests
  are still required.
- Protected output release held on missing, lost, stale or insufficiently scoped
  independent coverage. Test-only bypasses remain in test fixtures.
- A bounded local capture forwarder for operator-owned Tetragon JSONL. It never
  promotes process records into healthy sensors or complete coverage.

[Integration runbook and compatibility decisions](docs/member2_integration.md)
cover API routes, schemas, peer wiring, collector use and remaining acceptance gates.
[Current test/evidence results](docs/integration_validation.md) distinguish fixtures
from actual host observations. The original shared handoffs remain in `docs/handoffs/`.

## Validate

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m scripts.export_contracts --check
```

The original `agentguard/`, `platform/`, `sensors/`, two upstream test files, and
legacy contract schemas are retained. `python -m agentguard serve` still runs the
separate original policy workbench on port 8765. Its state, authority, synthetic
payroll totals and three-field broker protocol are not the integrated application's
state or protocol. Harness events must never be submitted as live evidence.

The original host reports are historical; use the latest Linux manifest for the
current implementation round. Docker and the host sensor were installed explicitly
in Ubuntu WSL; no kernel or GPU driver was changed. Full protected execution remains open.
See [Member 2 next tasks](docs/MEMBER_2_NEXT_STEPS.md) and the [contribution workflow](CONTRIBUTING.md).
