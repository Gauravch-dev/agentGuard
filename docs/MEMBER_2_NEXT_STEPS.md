# Latest application review return

Start here for the next round: [run, finish, verify and record handoff](NEXT_DEVELOPER_HANDOFF.md)
(26 October). It identifies what actually passed, what remains blocked, the
current Linux/Windows startup paths, real verification commands and the difference
between the existing hold/cleanup recorder and a future positive Finance demo.

The [26 October staging correction](staging_startup_fix.md) fixes the observed
policy-load timeout without relaxing admission or extending workload deadlines.
Real staging/hold/cleanup passes; the full monitoring requirements below remain open.

Latest Linux delivery implementation and honest acceptance state:
[Linux delivery return](linux_delivery_round.md). Before-start source witnesses,
expanded inherited-FD/readv/mmap/socket/curl probes, persistent final-drain recovery,
real owner-view checks, nine supplemental baseline samples and a local limitation
recording are implemented. Complete packet/process attribution, source clock/loss
proof and full admitted Finance/S01–S16 acceptance remain open. This is not final
protected MVP completion.

Final delivery ownership: @Gauravch-dev owns the remaining Linux implementation,
integration of both members' work, full testing, final end-to-end verification and
demo recording. Member 1's application implementation is handed over. Do not wait
for a separate Member 1 verification round; return application defects only when
they need Member 1's help. Follow the final delivery checklist in
[the application completion handoff](application_completion_round.md#final-delivery-ownership).

Current return: [Member 1 implementation completion and Linux tasks](application_completion_round.md).
Application code and supervisor-facing views are implemented and tested. Please
own the remaining bootstrap observation, supported-hook scope, process/packet joins,
clock/loss accounting and genuine protected Finance/S01–S16 acceptance. Pull this
checkpoint, implement and verify on Linux, then commit/push code and sanitized
evidence back and reply to issue #1. This supersedes earlier application requests.

Implemented return: [continuous supervisor results and remaining gates](linux_supervisor_round.md).
Linux revalidation, real continuous event/packet delivery, collector and service
restarts, conflict/revision checks and warmed strict model calls are recorded there.
The next platform work is observation from bootstrap birth, broader hook coverage,
genuine packet/process attribution and source clock/loss semantics. Protected
Finance/report/S01–S16 acceptance is conditional on that evidence; gates stay held.

See [the application review and current Linux return tasks](application_review_round.md)
for the checkpoint after `a95e564`. This supersedes the earlier return instructions:
revalidate replay/conflict semantics, complete continuous supervision, and return
real protected Finance/S01–S16 evidence without relaxing any admission gates.

---

# Current application return round

Linux follow-through is recorded in [the 25 October Linux return round](linux_return_round.md).
Real staging/cancellation/restart, scoped hooks, packet self-check and durable
authenticated hook delivery have been exercised. Full continuous source
supervision/coverage, protected model/report acceptance and remaining S01–S16
cases are still open; use that document's remaining-gates table for the next round.

The newer [application lifecycle integration handoff](application_lifecycle_round.md)
supersedes the earlier launcher-wiring requests below. Pull the new round, validate
the real staged application path and atomic admission marker, then complete live
sensor coverage, the trusted platform reviewer and model/S01–S16 acceptance.
Commit and push the Linux results for the next application review.

---

# Member 2 next round: Linux runtime, sensors, and live validation

Owner: @Gauravch-dev (Member 2). Start from the latest shared `main` branch after
this application-integration checkpoint is pushed. Please own the remaining Linux,
Docker, kernel/sensor, socket isolation, GPU/local-model setup and host-side
validation. Commit and push your completed round back to this same repository so
Member 1 can pull it, verify the application against real evidence, and continue.

## Current application checkpoint

Implemented and integrated: reviewed-template Task Authority; immutable signed
contracts and lifecycle; synthetic payroll and strict aggregate/model/output
brokers; evidence storage; Task-Effect Reconciliation Engine; authenticated FastAPI
routes; React dashboard; event translation/capture forwarding; and peer-authorization
adapters. The baseline has 115 passing tests, one genuine Linux-only skip and 13
passing subtests. Full MVP completion is not claimed: actual protected execution,
continuous independent coverage and a real model run have not been validated.

Do not replace the integrated application with the older policy workbench. The
workbench on port 8765 is a separate harness with different synthetic totals and a
legacy protocol. The integrated application uses port 8000 and
`dashboard/application/`. Existing fixtures never constitute live host evidence.

## 1. Pull and establish the Linux baseline

```sh
git switch main
git pull --ff-only origin main
uv sync --locked
uv run python -m agentguard audit --output platform/docs/linux_current_host.json
uv run pytest -q
```

Use your owned Linux host/VM. Record distro, kernel, architecture, cgroup version,
Docker Engine/security options, BTF, confinement support, user namespace behavior,
time synchronization and available GPU/model runtime. Existing Windows/WSL reports
are historical evidence, not proof of the current host's controls.

Select and record immutable image digests. Do not auto-pull floating images or
remove controls to pass a test. The initial socket/profile baseline supports local
rootful Docker without user namespaces; expand support only with explicit tests.

## 2. Implement the protected launcher and lifecycle

Primary files: `agentguard/platform.py`, `application/member2_bridge.py`,
`application/runtime_adapter.py`, and `platform/`.

- Implement protected `launch`, `inspect`, `terminate` and observation wiring. The
  current `Member2RuntimeAdapter` deliberately refuses protected execution.
- Use the authority-approved contract and fixed reviewed runtime profile. No
  agent/client-selected Docker arguments, commands, privileged mounts or image URLs.
- Enforce network isolation, filesystem policy, unprivileged UID/GID, dropped
  capabilities, no-new-privileges, seccomp, private namespaces and all resource limits.
- Provide a genuine task/version -> capsule/container -> host/cgroup/process mapping,
  including process start time/ticks and captured cgroup inode. No PID-only joins.
- Arrange startup admission so the server has registered the trusted binding and
  broker channel before untrusted Finance Agent code can request broker operations.
- Implement a watchdog that survives request failure/restarts; revoke channels on
  completion/failure and retain diagnostic evidence when cleanup is uncertain.
- Confirm actual cgroup/descendant exit on termination. A kill request or exited
  parent process alone must not produce a successful termination claim.

Do not turn readiness flags on merely because the fixed isolation lab passes. The
required sensor and broker/container gates must have real supporting evidence.

## 3. Wire and test the real per-capsule broker socket

Primary files: `agentguard/transport.py`, `application/broker_transport.py`, and
`application/member2_bridge.py::Member2ChannelAuthorizer`.

- Start one socket/channel per capsule under a private trusted host parent; mount
  only that capsule's socket directory and never the Docker control socket.
- Verify actual SO_PEERCRED, UID mapping, cgroup membership/inode, process birth and
  current task/channel authorization. Include descendants and PID/cgroup reuse cases.
- Test two real containers: cross-capsule access, forged task IDs, expired/revoked
  contracts and inherited stale credentials must be refused.
- Use the integrated four-field request envelope with request_id, not the legacy
  three-field workbench session. `agent_demo/finance_agent.py` is the supplied client.
- Validate ownership/mount permissions and pre/post-read peer checks on the actual
  kernel/container configuration. Keep provider keys/data/DB files outside capsules.

## 4. Complete live collectors, exporter, and continuous coverage

Primary locations: `sensors/`, `agentguard/sensors.py`,
`application/member2_exporter.py`, and the documented internal API routes.

- Install a reviewed pinned Tetragon version outside capsules; capture genuine
  process exec/exit events and supported file/connection hook behavior.
- Implement attributable network-flow collection. Record when the hook cannot
  observe a blocked attempt; do not invent traffic or infer encrypted contents.
- Add continuous source authentication, tailing/reconnect/checkpoint behavior,
  health checks, lost/export-failed/reset counters and coverage-window accounting.
- Cover all required process/file/connection/network event classes. Process-only
  records and EOF are insufficient. Sensor loss, stale data, unsupported hooks,
  dropped events or uncertain attribution must remain Unverified and hold release.
- Preserve source observation time, server receipt time, source identity and protected
  raw references separately. Keep raw arguments, tokens and confidential data out of
  committed fixtures and normal application logs.
- Use the existing shared schema. The Member 2 event extension is translated via
  `/internal/v1/member2/events`; coverage uses `/internal/v1/coverage`. Do not silently
  add required fields, change enums, or bypass source credentials to make integration work.

The existing capture forwarder is one-shot and process-only; it does not supply a
continuous sensor service, health proof or complete coverage on its own.

## 5. Set up and run the real local model outside the capsule

Please handle Linux/GPU driver/runtime installation and model hosting on your
machine. The application currently supports a fixed local Ollama endpoint at
127.0.0.1:11434 with `qwen2.5:7b`. Keep it loopback-only, record the actual model/runtime
version and model digest, and enable it only in the trusted broker environment.

Run the Finance Agent through all three brokers inside the protected capsule using
only the supplied synthetic fixture. Verify actual model-driven tool selection,
independently correct totals, internal report release and no model credentials in
capsule files, environment or descendants. Run both benign and injected lab inputs.
If the model refuses an injected instruction, record that result; a deterministic
adversarial driver can supplement testing but is not a real model attack result.
No external model/data transfer or real confidential payroll is authorized.

## 6. Finish the Linux acceptance round and return evidence

Run S01–S16 from the original shared handoff, including denied file reads, Python
and child/curl egress, DNS/IP/alternate-protocol attempts, raw-row output denial,
expiry/readiness failure, sensor loss, unexplained effects, cross-capsule isolation,
verified termination, fresh restarts and baseline comparisons.

Before pushing, run the complete combined suite, contract checks and relevant
static checks. Build/type-check the dashboard if changed. Scan any new dependencies
and secrets. Do not mark missing/unsupported observations as passing.

Return these artifacts in `docs/linux_handoff_results.md` and linked evidence:

| Required artifact | Contents |
|---|---|
| Reproducible runbook | Exact supported host setup and start/stop/rollback commands |
| Version manifest | Kernel, Docker, sensor/model versions and immutable image/model identifiers |
| Runtime evidence | Effective profile, real task/capsule/host/cgroup mapping and termination evidence |
| Collector evidence | Sanitized genuine events, raw references, scope/health/loss/coverage intervals |
| End-to-end result | Run/task IDs, broker receipts, verified internal report and concurrent findings |
| Acceptance matrix | Each S01–S16 result, evidence links and explicit unsupported/blocked/unverified cases |
| Remaining issues | Exact failure, expected vs observed behavior and where Member 1 should continue |
| Return reference | Pushed branch and exact commit SHA, plus concise validation summary |

## Shared boundaries and commit/push cycle

You may update the Linux runtime/transport/sensor code and application-side bridge
needed to complete that wiring. Preserve Task Authority approval checks, broker
payload restrictions, output verification, evidence integrity, schemas and the React
application. Coordinate genuinely necessary schema changes with a versioned decision
and compatibility tests rather than replacing interfaces wholesale.

1. Pull current `main` before starting each round; do not overwrite another member's changes.
2. Implement and verify the Linux work above; commit reproducible evidence and honest gaps.
3. Commit and push back to the same repository without force pushing. If branch rules
   require a pull request, use a neutral task branch and return its merged commit SHA.
4. Reply to the handoff issue with the commit/branch, tests, real evidence and remaining blockers.
5. Member 1 then pulls your changes, reruns combined checks and handles application
   follow-ups: real-evidence reconciliation, any bounded agent coverage-hold retry,
   API/dashboard integration adjustments and application regressions.
6. Repeat focused rounds until the full joint acceptance matrix is genuinely complete.

This checkpoint is ready to commit; the overall MVP remains open until those live
Linux/model and application acceptance gates pass.
