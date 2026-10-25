# Application lifecycle integration round

Recorded 25 October 2026. Based on shared main commit `8509e7a`.

The application now orchestrates Member 2's staged controller. **Protected AI
admission remains disabled in the supplied production configuration.** This round
does not establish new live Linux, sensor or model results.

## Implemented

- `application/staged_runtime.py` connects the actual `StagedCapsules` controller
  and `Member2ChannelAuthorizer` to the integrated broker transport. A dedicated
  socket loop serves each private channel; no capsule receives host credentials.
- `application/lifecycle.py` prepares a bootstrap, validates and persists the
  binding, opens its broker listener, and waits for admission. Preparation does
  not authorize broker requests or run agent code. The existing shared state
  `launch_requested` represents staging; no shared contract/event/schema changed.
- Admission requires current signed authorization, fresh continuous coverage for
  all existing mandatory scopes from bootstrap birth, an enabled local model,
  and a trusted live platform admission reviewer. The reviewer is **absent by
  default**. There is no HTTP or environment override. Fixture reviewers exist
  only in clearly labelled tests.
- The controller rechecks kernel/process identity and calls the application gate
  immediately before writing admission. Running state is committed under the
  same application lock before broker requests can proceed.
- Cancellation, expiry, monitoring loss and inspection failure durably revoke the
  broker channel before cleanup. Failed cleanup remains Unverified; retries do
  not restore access. A new revision is refused until previous containment is
  independently verified.
- A background monitor checks active tasks every second. Startup revokes and
  contains previous active workloads rather than resuming/re-admitting them;
  Member 2's independent watchdog remains responsible during service downtime.
  Graceful shutdown requests containment and closes listeners. Repeated identical
  cleanup errors are not appended every second.
- Natural exit requires confirmed descendants/channel cleanup, a trusted report,
  and coverage through the recorded containment time for business completion.
  The channel is revoked immediately. Late final coverage may arrive for at most
  30 seconds without reopening access; missing proof becomes failure.
  Reconciliation uses the recorded execution window separately from the later
  application decision time. Blocked/Unexplained/Unverified security findings
  remain separate from the business result.
- The Finance client retries only a coverage-held output, at most three retries
  with a one-second delay. Each uses a new idempotency key. Original denied
  receipts remain immutable; policy/schema/model errors are not retried.
- The dashboard explains staging, admission holds, revoked channels, unverified
  cleanup and final evidence waits. It offers admission rechecks, cleanup retries
  and new contract revisions. Active task details refresh every five seconds.

## Two integration fixes for joint Linux review

1. Admission publication now writes, flushes and permission-checks a complete
   marker before an exclusive atomic link exposes `admitted`. Explicit read-only
   permissions make it readable by UID 65532 under the Linux service's private
   umask. The previous direct create could expose an empty marker and could
   produce root-only permissions under umask 077. A genuine Linux permission and
   exclusivity regression is included and skipped on Windows.
2. Peer verification runs outside the socket event loop. It still occurs before
   and after reading a request. This prevents the authority lock used by admission
   or revocation from blocking the listener loop while a handler waits to close it.

## Optional Linux bootstrap staging

Default `python -m scripts.start_linux` behavior remains protected-launch refusal.
On the owned Linux host, build the reviewed **Finance** image from
`platform/profiles/Dockerfile.agent` using the explicit immutable Python base in
`platform/versions.json`. Do not substitute the socket-probe image. Start with:

```sh
python -m scripts.start_linux \
  --staged-image-id "$(docker image inspect --format '{{.Id}}' agentguard-finance:round2)" \
  --host-id linux-lab-01
```

Add `--lab-image-id` separately if testing the fixed isolation-lab endpoint.
This opt-in starts only a waiting bootstrap. It does not install sensors, download
images/models, enable a model, supply an admission reviewer or certify coverage.
An unadmitted bootstrap is bounded by the existing independent deadline watchdog.

Owner API additions (no caller-provided readiness/binding/permission fields):

| Request | Behavior |
|---|---|
| `POST /api/v1/tasks/{id}/launch` | With staged adapter: persist bootstrap mapping and return `launch_requested`, `agent_admitted: false`; otherwise retain default refusal |
| `POST /api/v1/tasks/{id}/admit` with `{}` | Recheck trusted gates; return explicit hold reasons or admit after all checks |
| `POST /api/v1/tasks/{id}/sync` with `{}` | Inspect lifecycle and reconcile completion/containment; also runs in the background |
| `POST /api/v1/tasks/{id}/terminate` | Works for staged or running tasks; revoke first, return 409 if exit is unverified |
| `GET /api/v1/tasks/{id}` | Adds application-only `execution` phase, reasons and revocation/admission status |

The runtime completion endpoint cannot force a terminal state using its submitted
payload; the staged adapter independently inspects the workload. HTTP success for
staging or a hold is not evidence that an agent was admitted.

## Next work for Member 2

1. Pull this application round and run the entire locked suite on Linux, including
   the new admission-marker regression. Run a real bootstrap through the optional
   staged application path. Capture identities, channel denial before admission,
   refusal reasons, cancellation, restart and verified cgroup cleanup. Retest the
   earlier socket lab after the atomic-marker and threaded-peer changes.
2. Complete supported file/connect hooks, network flows and durable continuous
   collection/coverage, including counter resets, outages and unavailable export
   metrics. Preserve the source timestamp conflict for joint semantic review.
   EOF, sampled zero counters and process observations do not certify coverage.
3. Register distinct authenticated sensor identities for all required sources.
   The convenience Linux startup still registers only the existing process
   sensor; it cannot attest independent network coverage. Add the complete
   private registry/provider startup only with real collector evidence.
4. Implement a trusted live admission reviewer using current effective profile,
   containment/peer acceptance, sensor readiness, clock compatibility and the
   exact approved Finance image/model configuration. Attach it through trusted
   application construction. Do not replace it with a constant `True`, an owner
   toggle, a stored passing lab result or a test fixture.
5. Configure and measure the approved local model outside the capsule, then run
   actual benign/injected Finance workloads and the remaining S01–S16 matrix.
   Keep full readiness false until the evidence supports those claims.
6. Commit and push the Linux results and sanitized run evidence back to this same
   repository. Member 1 will pull, review real reconciliation/report recovery,
   address application findings and repeat the joint acceptance round.

## Validation

The new lifecycle/controller/socket/model tests explicitly use simulation doubles.
They exercise authorization, durable revocation, coverage holds/loss, expiry,
restart, admission/setup failure, final coverage recovery/timeout, completion
claims and the background monitor. The UI was inspected against the real local
API with synthetic data and verified protected-launch refusal on Windows.

Local validation: **136 tests passed, five Linux-specific tests skipped, and 13
subtests passed**. Lint, formatting, type checks (19 source files), shared schema
compatibility, dashboard TypeScript/build, the offline changed-source secret scan
and the local browser check passed. The existing Starlette TestClient/httpx
deprecation warning remains. See `application_lifecycle_validation.json`.

Real Linux permission/peer checks require Member 2's host; no new live-model,
live-container or sensor acceptance is claimed here.
