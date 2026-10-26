# Next developer handoff: run, finish, verify and record AgentGuard

Recorded 26 October 2026. Reviewed code checkpoint: `5a65f17`.

## 1. Read this first

**The application and several genuine Linux experiments work. The full protected Finance MVP is not yet accepted.** This is not solely a Windows installation problem.

| What works at this checkpoint | What it proves |
|---|---|
| Task Authority, brokers, evidence, reconciliation and dashboard | Application behavior and policy enforcement have automated coverage. |
| Real Linux staging, source subscriptions and cleanup | A restricted bootstrap can start, monitoring can observe supported activity, admission can be held, and cleanup can be verified. |
| Actual socket/peer experiments | Aggregate requests can succeed; foreign callers and raw-row output can be denied in the explicit socket lab. |
| Actual local Ollama calls | The approved provider can return the expected tool choice on synthetic benign/injected documents. This is outside the protected Finance run. |
| Retained demo recordings | Real task creation, staging, admission refusal, monitoring review and cleanup. They do not show a completed Finance report. |

The latest [staging smoke result](linux/staging_startup_review.json) records `passed: true`, **`agent_admitted: false`**, **`no_report_released: true`** and **`full_protected_mvp_complete: false`**. Its roughly 56.7-second staging time is one run, not a performance guarantee. The test passes because it expects the hold and verifies cleanup.

The original positive continuous experiment remains [unsuccessful](linux/continuous_delivery_review.json). Do not substitute a passing hold/cleanup experiment for positive acceptance.

### Two environments, different limits

- **Windows without Linux/Docker:** the real dashboard/API works. Start safety check refuses with `linux_host` and no trusted binding. No capsule or Finance agent starts.
- **Configured Linux host:** staging, supported sensor observation and cleanup work. The Finance agent remains unadmitted while required coverage and other live checks are unsatisfied.

Installing WSL addresses the first environment limitation. It does not fix the Linux implementation blockers below. Earlier runbooks contain historical statements about what was installed on their author's machine; inspect the current host rather than copying those assumptions.

## 2. Work remaining and where to continue

| Work item | Starting points | Required verification |
|---|---|---|
| Observation for the full initial interval | `agentguard/prebirth.py`, `agentguard/supervisor.py`, `agentguard/network_tap.py` | Process/file witnesses already precede startup, but packet attachment and initial attribution/loss gaps still prevent whole-interval coverage. Supply genuine evidence covering the required interval. |
| Supported file/network mechanisms | `agentguard/hook_policy.py`, `platform/profiles/scope_probe.py`, `scripts/linux_scope_lab.py` | Define and test actual scope. Mmap permission checks do not observe individual page reads; unavailable mechanisms remain explicit. |
| Packet-to-process attribution | `agentguard/network_tap.py`, `scripts/linux_packet_stream.py`, sensor normalization | Prove the actual originating process/cgroup with birth identity. Namespace traffic alone is insufficient. |
| Source clock compatibility | `agentguard/source_time.py`, `agentguard/sensors.py`, `scripts/linux_source_audit.py` | Resolve genuine source-time reversals with a reviewed time model. Retain original timestamps and conflicts. |
| End-to-end loss and export accounting | `agentguard/observer_health.py`, `agentguard/supervisor.py`, `agentguard/export_queue.py` | Measured source loss, gaps, resets and delivery failures must have clear semantics. Missing metrics remain unknown. |
| Protected Finance completion and recovery | `application/staged_runtime.py`, `application/lifecycle.py`, `application/brokers.py`, `agent_demo/finance_agent.py` | Actual admission, model-driven broker actions, validated internal report, final coverage, revocation and independently verified descendant exit. |
| Joint acceptance and performance | [S01-S16 matrix](linux_delivery_round.md#s01s16-acceptance-state), `scripts/linux_baseline_lab.py` | Finish outstanding actual agent scenarios. Supplemental probe timings are not full Finance overhead measurements. |

Read [the Linux delivery return](linux_delivery_round.md), [startup correction](staging_startup_fix.md) and [application completion handoff](application_completion_round.md) before changing these paths.

### Proposed behavior-security capabilities are a separate unfinished layer

The presentation's complete solution also includes learned normal profiles, behavioral anomaly detection, numerical risk scoring and graduated adaptive responses. The reviewed implementation has deterministic permission/effect reconciliation and existing denials/containment, **not that complete learned detector and risk engine**.

If the next delivery claims those capabilities, implement and evaluate them too: reviewed benign baselines, role/context separation, held-out legitimate/drift cases, explained score factors, separate evidence confidence, response policies and recovery tests. Preserve hard permissions; learning never grants access. Coordinate any shared schema extensions through a versioned decision and compatibility tests. Otherwise label them as proposed scope in the demo and documentation.

## 3. Rules for the next round

- Use synthetic payroll and owned lab inputs only. Keep model calls local to the approved provider.
- Preserve signed permissions, peer identity checks, source authentication, report validation and admission/coverage/conflict gates.
- Do not use constant-true reviewers, fabricated telemetry, injected complete coverage, rewritten timestamps or a manual admission marker to make the demo pass.
- Keep credentials, database keys, raw journals and host-private diagnostics outside capsules and Git. Keep the integrity key stable for an existing database.
- Run one interactive control plane on loopback port 8000. Do not expose the application or Docker daemon publicly.
- Keep passing and failing experiments, recording their exact scope. Use new output paths instead of overwriting committed historical evidence.
- Fix source gaps, not their labels. A passed unit test, source heartbeat or successful packet export is not whole-task safety evidence.

## 4. Obtain the current code and choose a host

On an existing checkout, inspect local changes before updating:

```sh
git status --short
git pull --ff-only origin main
git log -1 --oneline
```

For a new checkout only:

```sh
git clone https://github.com/Gauravch-dev/agentGuard.git agentGuard
cd agentGuard
```

Run subsequent commands from the repository root. Do not reset another developer's uncommitted work or force-push.

### Windows: UI/API walkthrough only

Requirements: Python 3.12+, uv, Node 22.12+ and npm. In PowerShell:

```powershell
uv sync --locked
if ($LASTEXITCODE -ne 0) { throw 'Python dependency setup failed' }
Push-Location dashboard/application
try {
    npm.cmd ci --ignore-scripts
    if ($LASTEXITCODE -ne 0) { throw 'Dashboard dependency install failed' }
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw 'Dashboard build failed' }
} finally { Pop-Location }
.\scripts\start-local.ps1
```

Stop if dependency setup fails. The script prints a session owner token and uses a fresh session database. Open `http://127.0.0.1:8000`, paste the token into the masked field and connect. Record task creation/permissions, activity, notes and the genuine environment refusal if needed. Do not call this a successful Linux/AI demo. Keep the terminal open; Ctrl+C stops the server.

### Optional: prepare WSL2 on a Windows machine

If Linux is missing and the machine owner chooses a local Linux lab, run the first command in Administrator PowerShell:

```powershell
wsl --install -d Ubuntu
```

Complete any requested Windows restart and Ubuntu first-run account setup. Then check that the distribution uses version 2 and enter its trusted root shell:

```powershell
wsl --list --verbose
wsl --distribution Ubuntu --user root
```

Continue with the Linux steps below inside Ubuntu. Verify actual systemd, cgroup and BTF support before installing the project services. Local CPU/GPU capacity may limit the approved model; another host's warm timings are not a guarantee. Installing WSL alone does not resolve the project's remaining monitoring/acceptance blockers.

### Linux: supported integration environment

Use a trusted root Bash shell on the owned Ubuntu lab host. The existing launcher baseline requires rootful Docker Engine on that same Linux host, with local peer/process/cgroup visibility. A Docker client pointed at a remote daemon or separate Docker Desktop VM is not an equivalent verified setup.

Required checks:

```sh
id -u
uname -r
docker info
test -f /sys/fs/cgroup/cgroup.controllers
test -f /sys/kernel/btf/vmlinux
```

The user ID must be zero; Docker must work locally; cgroup v2 and kernel BTF must exist. These checks are prerequisites, not complete readiness certification.

On an unconfigured owned host, first arrange supported Ubuntu/systemd, Python 3.12+, uv, Node 22.12+/npm, and the host's reviewed GPU/runtime prerequisites. Review these existing setup scripts before executing them as root:

- `sh platform/setup/install_docker.sh`: installs the selected signed Ubuntu Docker packages, starts the daemon and refuses conflicting existing installations.
- `sh platform/setup/install_ollama.sh`: installs the pinned, checksum-verified runtime and loopback-only `agentguard-model` service. Requires `zstd` and `curl`; it does not provision the model weights.
- `sh platform/setup/start_tetragon.sh`: requires `cosign`, verifies the pinned sensor signature and starts the managed privileged host-sensor container with no published ports.

On an existing configured host, reuse reviewed services and state. The model installer deliberately refuses an existing installation. Provision the approved local model separately and check its exact digest against `platform/versions.json`; the model name alone is insufficient. Do not silently approve a changed model or image to get past a check.

### Prepare the application environment and images

Use the existing reviewed Linux environment if available. For a new repository-local environment:

```sh
uv sync --locked
. .venv/bin/activate
```

If reusing the existing lab environment, activate `/var/lib/agentguard/venv/bin/activate` instead. Use the same selected environment in each terminal.

Build the dashboard:

```sh
(
    set -eu
    cd dashboard/application
    npm ci --ignore-scripts
    npm run build
)
```

The configured host already has image tags `agentguard-finance:round2`, `agentguard-socket-lab:round1` and `agentguard-probes:delivery`. Tags only select local images; the launcher receives their immutable IDs. Compare them with the last reviewed [version manifest](linux/version_manifest.json). If rebuilding, record and review the new IDs.

For example, to build a missing Finance image from the reviewed immutable base:

```sh
python_base=$(python -c 'import json; print(json.load(open("platform/versions.json"))["python_base"])')
docker build --build-arg PYTHON_BASE="$python_base" \
  -t agentguard-finance:round2 -f platform/profiles/Dockerfile.agent .
```

Keep `Dockerfile.agent` separate from socket/probe images. The probe dependency review has outstanding advisory matches; its presence is not production-image approval. Do not mount the repository, synthetic raw payroll, provider configuration, credentials, database or Docker socket into the Finance capsule.

## 5. Run the real Linux application

Stop any Windows preview on port 8000 before starting the Linux server. Otherwise Windows/WSL localhost forwarding can leave the browser connected to the wrong backend. Do not terminate an unrelated process just because it owns that port.

In terminal A, from the repository root with the selected environment active:

```sh
set -eu
umask 077
sh platform/setup/start_tetragon.sh
systemctl start agentguard-model
python -m scripts.linux_sensor_registry --host-id linux-lab-01

finance_image=$(docker image inspect --format '{{.Id}}' agentguard-finance:round2)
model_digest=$(python -c 'import json; print(json.load(open("platform/versions.json"))["approved_model_digest"])')

python -m scripts.start_linux \
  --staged-image-id "$finance_image" \
  --host-id linux-lab-01 \
  --sensor-registry /var/lib/agentguard/control/sensors.json \
  --approved-model-digest "$model_digest" \
  --continuous-observers
```

Stop and investigate any failed setup command before starting the server. The host ID must match the registry and runtime. Keep this terminal open. Source credentials are distinct; creating the registry does not certify monitoring.

Open `http://127.0.0.1:8000`. Retrieve the owner token privately in terminal B, outside the recording:

```sh
python -c 'import json; print(json.load(open("/var/lib/agentguard/control/credentials.json"))["owner"])'
```

Paste it into the masked **Owner access token** field and choose **Connect workspace**. Do not show the credential terminal on video or paste the token into an issue. The server does not print the Linux owner token to its log.

For model troubleshooting, inspect loopback `/api/tags` and `/api/ps` on port 11434, actual approved digest and service state. A model can unload while idle. Warm it using approved synthetic input, then repeat the measured check without extending its acceptance deadline.

## 6. Verify the current staging/hold/cleanup workflow

In terminal B, with the same checkout/environment and the real server running:

```sh
umask 077
mkdir -p var/verification
verify_dir=$(mktemp -d var/verification/run-XXXXXXXX)
python -m scripts.linux_staging_smoke --output "$verify_dir/staging-smoke.json"
```

Expected current behavior:

1. A new approved synthetic task is created.
2. A real restricted bootstrap stages; process/hook witnesses precede its birth.
3. Admission is refused while mandatory monitoring requirements are missing.
4. No Finance code is admitted and no business report appears.
5. The script requests cleanup, verifies descendant exit and preserves evidence.

The smoke script currently expects exactly nine successful checks, including the hold. After positive admission is genuinely implemented, add/update a separate positive test and retain equivalent negative coverage for deliberately missing requirements. Do not remove the refusal assertion merely to obtain green results.

The smoke test creates and cleans up its own task. It does not create a completed Finance task for a recording. Keep manual recording tasks separate.

If this check fails, inspect the root-private server/runtime/observer diagnostics for its actual capsule. The UI's generic staging message is not the root cause. The previous cold policy-load timeout was fixed in `13ac7c8`; that fix retained all hooks, witnesses and the original workload deadline.

## 7. Run the checks after implementation changes

Run live labs sequentially, away from an interactive recording. They create separate test capsules and some start their own local servers; concurrent sensor setup or load can distort results. Recompute these shell variables in the terminal used for the labs:

```sh
umask 077
mkdir -p var/verification
verify_dir=$(mktemp -d var/verification/run-XXXXXXXX)
finance_image=$(docker image inspect --format '{{.Id}}' agentguard-finance:round2)
socket_image=$(docker image inspect --format '{{.Id}}' agentguard-socket-lab:round1)
probe_image=$(docker image inspect --format '{{.Id}}' agentguard-probes:delivery)
model_digest=$(python -c 'import json; print(json.load(open("platform/versions.json"))["approved_model_digest"])')
```

Run each command separately, inspect its result and retain failures before proceeding:

```sh
python -m agentguard audit --output "$verify_dir/host-capabilities.json"
python -m scripts.linux_socket_lab --image-id "$socket_image" --output "$verify_dir/socket.json"
python -m scripts.linux_scope_lab --image-id "$probe_image" --output "$verify_dir/scope.json"
python -m scripts.linux_model_lab --approved-model-digest "$model_digest" --output "$verify_dir/model.json"
python -m scripts.linux_delivery_lab --image-id "$finance_image" --approved-model-digest "$model_digest" --output "$verify_dir/delivery.json"
python -m scripts.linux_continuous_lab --image-id "$finance_image" --approved-model-digest "$model_digest" --output "$verify_dir/continuous.json"
python -m scripts.linux_source_audit --output "$verify_dir/source-review.json"
python -m scripts.linux_baseline_lab --image-id "$probe_image" --iterations 3 --output "$verify_dir/probe-baseline.json"
```

Interpret results by scope:

- `linux_socket_lab` uses an explicit socket harness; it does not invoke the real model or release a full Finance report.
- `linux_model_lab` verifies provider responses, not capsule admission. Its zero exit code alone is insufficient: inspect both runs for the expected operation, exact approved aggregate payload and actual model identity. Retain cold-start failures separately.
- `linux_delivery_lab` exercises real owner views and held admission. Its successful output deliberately says `delivery_complete: false`.
- `linux_continuous_lab` is an actual observation/recovery acceptance experiment whose original event criteria must remain intact. Its historical failure must not be replaced with a passing negative test. Even a future pass is not, on its own, a completed Finance task.
- The three-iteration probe baseline is a small supplemental experiment, not a production percentile, detector-accuracy result or full Finance overhead measurement.
- Source audits and model-registry queries may require internet access for public source/advisory or software assets. They do not authorize transferring task data to an external model.

Run regression/static checks and the dashboard build:

```sh
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m scripts.export_contracts --check
(
    set -eu
    cd dashboard/application
    npm run build
)
```

The convenience `python -m scripts.integration_validate_round --label linux` runs the Python checks and writes `docs/linux/validation_linux.json`; preserve the old report if keeping both checkpoints and review that tracked change. It does not establish full MVP acceptance or build the dashboard for you. Rerun the existing dependency/secret reviews when dependencies, images or publishable artifacts change.

Historical results at this handoff: 232 Linux tests and 13 subtests in the committed Linux validation; 207 Windows tests, 25 Linux-specific skips and 13 subtests in the latest local application run. Counts can change with added tests. Passing tests are not detection accuracy or evidence that all S01-S16 scenarios passed.

## 8. What a successful protected Finance run must prove

After the real mandatory blockers are resolved, use the production startup above and a fresh approved task. Do not run the agent directly on the host or manually create its admission marker.

Required positive evidence for the same task/version/capsule:

- Real signed contract and trusted runtime identity, with no simulation flags.
- Actual admission through the live reviewer after complete required monitoring and profile checks.
- Completed Data Broker, actual approved Model Broker and validated Output Broker receipts.
- Correct internal department report, independently checked against trusted synthetic totals.
- Coverage for required classes across the execution interval, including final evidence after exit; no unresolved source contradictions or fabricated process joins.
- Verified descendant exit and durable channel revocation before final completion.
- Business outcome `completed`, evidence integrity verified, and every concurrent security finding reviewed separately.

The running UI flag `agent_admitted: true` is transient. After a completed run it becomes false; retained admission evidence must prove that the agent actually ran. A report draft, zero process exit, or green evidence-chain badge alone is insufficient.

### API evidence check for a completed candidate run

From terminal B, enter the **full task ID from the run being verified**, not a short sidebar suffix. This is read-only, uses the actual owner credential without printing it, and inspects that exact revision:

```sh
read -r -p 'Full task ID from this run: ' AG_VERIFY_TASK_ID
export AG_VERIFY_TASK_ID
python - <<'PY'
import json
import os
import re
from pathlib import Path
import httpx

task_id = os.environ['AG_VERIFY_TASK_ID']
if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', task_id):
    raise SystemExit('Invalid task ID')
owner = json.loads(Path('/var/lib/agentguard/control/credentials.json').read_text())['owner']
with httpx.Client(base_url='http://127.0.0.1:8000',
                  headers={'Authorization': 'Bearer ' + owner},
                  trust_env=False, follow_redirects=False, timeout=15) as client:
    def get(path):
        response = client.get(path)
        response.raise_for_status()
        return response.json()
    base = '/api/v1/tasks/' + task_id
    task = get(base)
    version = task['contract']['contract_version']
    result = get(base + f'/result?version={version}')
    events = get(base + f'/events?version={version}')
receipts = [e['body']['response']['receipt'] for e in events if e['kind'] == 'broker']
operations = {r['operation'] for r in receipts
              if r['verdict'] == 'allowed' and r['effect_status'] == 'completed'}
summary = {
    'task_id': task_id,
    'contract_version': version,
    'business_outcome': result['business_outcome'],
    'actual_admission_recorded': any(e['kind'] == 'admission'
        and e['body'].get('agent_admitted') is True for e in events),
    'three_broker_operations_completed': {
        'data.get_department_totals', 'model.generate_report_draft',
        'output.save_department_summary'} <= operations,
    'reports_released': len(result['reports']),
    'integrity_verified': result['integrity_verified'],
    'simulated': result['simulated'],
    'channel_revoked': task['execution'].get('channel_revoked'),
    'verified_exit_recorded': any(e['kind'] in {'task_result', 'termination'}
        and e['body'].get('descendants_exited') is True for e in events),
    'unverified_findings': sum(f['classification'] == 'Unverified' for f in result['findings']),
    'unexplained_findings': sum(f['classification'] == 'Unexplained' for f in result['findings']),
}
print(json.dumps(summary, indent=2))
PY
unset AG_VERIFY_TASK_ID
```

This is a useful evidence summary, **not a complete acceptance oracle**. Verify report values, original sensor provenance, coverage intervals, approved model digest and all S01-S16 cases separately. Retain the task/capsule IDs and exact code/image/model versions with the result.

### Benign and injected runs

The agent client supports `--document benign|injected`, but the current fixed image bootstrap invokes its default benign workflow. The owner API does not accept arbitrary commands or a document override. For an admitted injected case, implement a narrowly reviewed lab selector or reviewed image/profile variant with tests, keeping the fixed entrypoint, contract and admission boundary. Do not bypass the launcher with `docker exec` and count that as an admitted attack run.

If the actual model ignores/refuses the malicious instruction, record that result. A separately labeled deterministic adversarial driver can demonstrate broker/OS denials, but cannot replace actual model behavior.

## 9. Record the demo

### Current truthful walkthrough

On the configured Linux server:

1. Connect with the masked owner token.
2. Choose **New task -> Review permissions -> Create task**.
3. On **Overview**, choose **Start safety check**. Explain that preparation is not agent admission; allow real sensor setup time.
4. If staging succeeds, choose **Check readiness**. Show the real remaining hold reasons.
5. Show **Activity**, **Security checks** and **Report**. Leave missing coverage and the absence of a released report visible.
6. Save a review note describing the limitation.
7. Choose **Stop & clean up**. Show independently verified cleanup and revoked access.

Call this a **real staging/admission-hold/cleanup demonstration**, not a successful protected Finance demonstration. A staging failure is a failure to investigate, not a successful admission hold.

The existing `scripts/record_delivery_demo.mjs` automates this limitation workflow only. It explicitly expects refusal and no report and writes `delivery_complete: false`. It is unsuitable as the positive Finance recorder without a separately reviewed change.

To use it, the Linux host needs Node and an already reviewed local directory containing the `playwright` package and its installed browser. The package root is the directory from which `playwright` resolves, for example a reviewed `node_modules` directory; the project does not declare Playwright as a dependency or download it automatically. Set the actual absolute path interactively:

```sh
read -r -p 'Reviewed Playwright package root: ' AG_PLAYWRIGHT_ROOT
export AG_PLAYWRIGHT_ROOT
python -c 'import json; print(json.load(open("/var/lib/agentguard/control/credentials.json"))["owner"])' |
  node scripts/record_delivery_demo.mjs --playwright-root "$AG_PLAYWRIGHT_ROOT"
unset AG_PLAYWRIGHT_ROOT
```

The pipe supplies the token on stdin without showing it. Do not pass credentials as command-line arguments. If using a reviewed installed browser instead of the package's browser, the recorder accepts `--browser-channel chrome` or `--browser-channel msedge`.

**Recorder file effects:** it saves video/screenshots beneath ignored `var/demo/<run_id>/` and rewrites the tracked `docs/linux/demo_recording.json`. Inspect/preserve any existing manifest before running; use a new dated public manifest when keeping multiple recordings. Do not discard unrelated edits or replace the old experiment's evidence with a different outcome. Failures can leave partial private artifacts; inspect cleanup separately.

See [the retained media](demos/README.md) for the existing genuine recordings and their declared limits.

### Final positive recording, after the requirements pass

Use a manual screen recording or a new positive recorder that verifies the real API alongside the UI. Show:

- Exact build and approved synthetic task, with its effective permissions.
- Successful verified admission, not merely container preparation.
- Real model-driven work through all three brokers and a correct released internal report.
- Independent observations, complete required coverage and explained security findings.
- A controlled forbidden action and its actual outcome, without claiming a blocked attempt leaked data.
- Legitimate continuation where supported, plus verified process/channel cleanup.
- Separate measured timings and any remaining limitations.

Keep unimplemented learning/risk features labeled as proposed. If demonstrating them as completed capabilities, include actual baseline, drift, score/explanation and response evidence as well. Do not edit DOM/statuses, replay fixture data as live observations or hide unresolved findings.

Keep the credential terminal, tokens, raw arguments, private host paths and databases out of the video. Supply the video through the team's agreed location and link it from the handoff; prefer a small manifest and screenshots in Git rather than another large binary. If recording publication changes, preserve scope notes and original evidence references.

## 10. Troubleshooting and safe shutdown

| Symptom | Meaning / next check |
|---|---|
| `linux_host`, missing trusted binding on Windows | The host cannot run the Linux capsule path. Use a configured Linux environment; do not create a fake binding. |
| `STAGING_FAILED` | Inspect private controller/source logs. Check source policy setup, original deadline, permissions and image identity. Retry with a fresh authorized run after verified cleanup. |
| Waiting for admission | Bootstrap may be staged, but the Finance agent has not started. Read actual hold reasons. |
| Unknown loss or source not verified | Monitoring cannot certify completeness. Resolve the metric/source problem rather than replacing unknown with zero. |
| Model disabled/unloaded/digest mismatch | Check the trusted local service, exact digest and warm state. Keep inference outside the capsule. |
| Report absent or final coverage pending | Verify genuine output receipt, report checks, process exit and final monitoring; task completion cannot be forced from a runtime callback. |
| Contradictory evidence | Preserve immutable originals and conflicts. Investigate; do not clear the ledger to recover the same revision. |
| Cleanup unverified | Access remains revoked. Inspect the exact owned container/cgroup and descendants; a stop request alone proves nothing. |
| Linux smoke passes but no report exists | Expected for the current refusal/cleanup test. Positive Finance acceptance is a different requirement. |

Stop the foreground application with Ctrl+C. It attempts revocation, containment and observer shutdown. Verify task cleanup through the API and the matching managed runtime/cgroup records. Retain uncertain diagnostics. Do not use a broad Docker prune, kill unrelated processes or delete the evidence database to clear a UI error.

## 11. Return the completed round

Commit focused code changes, regression tests, updated run instructions and sanitized results. Include:

- Exact commit/branch, host/kernel/tool versions and immutable image/model identifiers.
- Which actual tasks were admitted, which reports were released and how totals/cleanup/coverage were independently verified.
- Each S01-S16 result with evidence and explicit blocked/unsupported/unverified entries.
- For learned detection, if implemented: dataset definition, reviewed baseline/version, held-out results, false alerts, risk explanation examples, latency and legitimate-work impact.
- New recording location, screenshot/manifest references and truthful demo scope.
- Remaining blockers and ownership. State clearly whether this is staging-only progress or completed positive acceptance.

Before publication, review changed files, scan for credentials/private paths, rerun appropriate checks, then commit with the configured human Git identity and push without force. Use neutral commit names and no automated attribution trailers. Reply to issue #1 with the return reference and evidence; keep it open while required acceptance remains incomplete.

Do not mark the original MVP complete until actual protected Finance/report acceptance and the required joint scenario matrix pass. Do not mark the broader behavioral solution complete while learning, explained numerical scoring and its response evaluation remain proposed.

This handoff's commands are checked against the reviewed source and interfaces. They do not represent a fresh Linux run by the documentation author; the next operator must execute them on the actual target host and return its results.
