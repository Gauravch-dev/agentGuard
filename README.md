# AgentGuard 2.0 — integrated application and Linux platform work

**Status: partially implemented MVP. The full handoff is not complete.**

[Recordings and screenshots](docs/demos/README.md) include both retained demo videos,
the redesigned UI, and before/after staging evidence, with hashes and honest scope notes.

The [redesigned dashboard](docs/dashboard_redesign.md) provides guided task setup,
a progress tracker and separate Overview, Activity, Security checks and Report views.
Use **New task → Review permissions → Create task → Start safety check**.

The [26 October staging correction](docs/staging_startup_fix.md) fixes a cold sensor
policy-load timeout and adds visible launch progress. A real staging/hold/cleanup
check passes, along with 232 Linux tests and 13 subtests. Full AI admission remains
held on the independent monitoring gaps below.

The latest [Linux delivery return](docs/linux_delivery_round.md) adds witnessed
process/file/socket subscriptions before startup, expanded live scope probes,
persistent queue recovery, real owner-view verification, measured probe baselines
and a local dashboard limitation/cleanup recording. It passes 231 Linux tests and
207 Windows tests (24 Linux-specific skips), plus 13 subtests on each. Packet/process
attribution, consistent source clock/loss proof and full Finance acceptance remain blocked.

| Area | Verified today | Remaining |
|---|---|---|
| Application | Task Authority, brokers, evidence, reconciliation, dashboard and real staged cancellation/restart checks | Protected report recovery with complete monitoring |
| Linux runtime | Restricted containers, peers, watchdog, verified cleanup and witnessed process/hook subscriptions before startup | Whole-interval coverage, including the later packet attachment |
| Sensors | Continuous authenticated export, expanded FD/readv/mmap/socket/curl probes and persistent replay | Remaining unsupported mechanisms, genuine packet/process join and source clock/loss proof |
| AI model | Pinned Ollama/Qwen setup and actual benign/injected provider calls | Complete protected benign/injected Finance runs |
| Acceptance | 231 Linux tests, 207 Windows tests, genuine owner/socket/scope checks, nine probe baseline samples and a limitation recording | Admitted Finance/report continuation, full S01–S16 and Finance baseline/performance comparisons |

## Latest Linux return round

The connected supervisor now exports genuine process, file/connect and independent
packet observations continuously. Live experiments verify collector restart,
durable replay after a service restart, contradiction holds, revision isolation and
cleanup. The stricter warmed local model also passed the synthetic provider checks.

See [current supervisor results and startup commands](docs/linux_supervisor_round.md)
and [the return history](docs/linux_return_round.md). Protected Finance admission
remains held because pre-birth observation, broader scope, packet/process attribution
and source clock/loss proof remain incomplete. Earlier checkpoints below are historical.

## Latest application lifecycle round

The application now connects Member 2's staged launcher to persisted task bindings,
private broker listeners, admission holds, background lifecycle checks, cancellation
and restart cleanup. Known sensor outages hold reports even when they start after
the last broker action. The dashboard explains waiting/cleanup states, and the
Finance client has bounded retries for coverage-held output.

Production admission remains disabled: the trusted live platform reviewer, complete
continuous sensor coverage and approved model setup are still missing. An optional
Linux startup flag stages only a waiting bootstrap. See the
[application lifecycle round and next Linux tasks](docs/application_lifecycle_round.md)
for exact APIs, validation limits and the return handoff.

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

## Earlier application integration checkpoint

This integration builds on Member 2's repository, commit
`198aea6515954130ed58ed21601a23be767596a0`. It adds the Member 1 FastAPI/React application and
explicit integration bridges. The earlier Member 1 workspace is preserved.

**Protected AI execution is still disabled.** Real two-container checks now pass,
but continuous sensor coverage and complete application admission are still pending.
The prior application checkpoint used a Windows host without WSL or Docker. Its
historical validation did not claim live Linux/model results; the newer Linux
experiments are linked above. Dependency/advisory queries transfer no application data.

## Run and test on the configured Ubuntu WSL host

On the configured laptop, Linux, Docker, the Linux Python environment and the built
dashboard are already available. Open Ubuntu using `wsl -d Ubuntu` in PowerShell,
then change to your checkout directory. From its root in Ubuntu, using the reviewed
rootful host account:

```bash
source /var/lib/agentguard/venv/bin/activate
python -m scripts.start_linux --lab-image-id "$(docker image inspect --format '{{.Id}}' agentguard-capsule:lab)"
```

Keep that terminal open. Open [http://127.0.0.1:8000](http://127.0.0.1:8000), paste
the owner token from the root-private control state, click **Connect workspace**, then **New task**. If the server is already
running, use it instead of starting another server on the same port. The authorized
host operator can retrieve its current owner token in another activated terminal:

```bash
python -c "import json; print(json.load(open('/var/lib/agentguard/control/credentials.json'))['owner'])"
```

The Linux service preserves its private credentials and database outside capsules.
Stop it with Ctrl+C. **Start safety check** prepares an isolated bootstrap and
registers its runtime identity. **Check readiness** still holds AI admission while
required monitoring is incomplete. Staging alone produces no business success or report.

In another Ubuntu terminal, open the checkout and activate the same environment.
Run the automated suite or the complete regression/static checks:

```bash
python -m pytest -q
python -m scripts.integration_validate_round --label linux
```

With the application running, test the real owner API and fixed Docker lab, then
the real two-container broker, raw-row denial and watchdog checks:

```bash
python -m scripts.linux_application_smoke
python -m scripts.linux_socket_lab --image-id "$(docker image inspect --format '{{.Id}}' agentguard-socket-lab:round1)"
```

Those lab commands should report `"passed": true`. They do not invoke a model or
bypass output coverage. Source sensor gaps remain Unverified; a passing lab is not
full AI-agent acceptance. See the [Linux runbook and S01–S16 matrix](docs/linux_handoff_results.md)
for pinned image builds, sensor startup, raw evidence and remaining cases.

## Windows application preview

This runs the integrated UI/API on Windows. Use the Linux instructions above for
real Docker/sensor experiments. After setup, start it from the repository root:

```powershell
.\scripts\start-local.ps1
```

Open http://127.0.0.1:8000 and paste the generated local owner token. The dashboard
shows real platform capability/preflight results, contracts, events, findings and
reports. Creating a task works; protected launch correctly refuses on this host.
The Windows script uses a fresh synthetic database and ephemeral keys each session;
its state is separate from the Linux service. Run one server on port 8000 at a time.

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
  birth, cgroup inode and current contract/channel checks. The fixed real
  two-container tests pass; broader stale-channel and full AI acceptance remain open.
- Protected output release held on missing, lost, stale or insufficiently scoped
  independent coverage. Test-only bypasses remain in test fixtures.
- A bounded local capture forwarder for operator-owned Tetragon JSONL. It never
  promotes process records into healthy sensors or complete coverage.

[Integration runbook and compatibility decisions](docs/member2_integration.md)
cover API routes, schemas, peer wiring, collector use and remaining acceptance gates.
[Latest Linux validation](docs/linux/validation_linux.json) and
[Windows validation](docs/linux/validation_windows.json) record current checks.
The [earlier application checkpoint results](docs/integration_validation.md) are
historical. The original shared handoffs remain in `docs/handoffs/`.

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
