# Member 1 + Member 2 integration — 24 October 2026

Upstream: https://github.com/Gauravch-dev/agentGuard, commit
`198aea6515954130ed58ed21601a23be767596a0`. The application integration is prepared on
`member1-integration`; upstream platform, sensor and legacy application source
is unchanged. The next owner handoff is in `MEMBER_2_NEXT_STEPS.md`. The combined application deliberately keeps protection disabled.

## Compatibility decisions

| Interface | Integrated behavior |
|---|---|
| Task contract | Member 1 creates its fixed reviewed Finance template; it also passes Member 2's validator. Broader legacy limits/roles are not silently imported. |
| Shared event | `contracts/security_event.schema.json` retains the original handoff fields/enums. Member 2's separate hyphenated schema remains unchanged. |
| Member 2 event extension | `POST /internal/v1/member2/events` accepts `{wire_format:"member2-normalized-1.0",event:<upstream normalized event>}`. Registered sensor/host/source and trusted capsule mapping are still required. |
| Receipt metadata | Original `observed_at` stays in the shared event. Application receipt time/sensor ID stay in its envelope. Upstream `received_at` and bounded normalizer `details` are atomically saved as `member2_metadata`. Duplicate re-delivery does not overwrite first receipt metadata. |
| Supported sensor events | Only genuine upstream process_exec/process_exit records; partial coverage stays partial. Unsupported hooks/shapes or metadata extensions fail closed. No policy-harness promotion. |
| Broker wire | The application uses `{schema_version,request_id,operation,payload}` and durable idempotency. Member 2's legacy three-field session is unchanged and is not accepted silently by this endpoint. Use the supplied `agent_demo` client. |
| Payroll fixture | The integrated app uses Member 1's trusted aggregate fixture. Member 2's separate workbench uses different synthetic totals; they are deliberately not mixed or auto-approved. |
| Database | Integrated `var/` SQLite ledger is separate from legacy `.agentguard/`. No migration, shared signing key or implicit transfer of approvals is performed. |

`contracts/member2_transfer.schema.json` references the preserved upstream extended
schema. Runtime semantic checks restrict it to the supported normalizer output.
The original `task_contract` and `security_event` schemas are not extended with
simulation/receipt/source-specific fields. Joint schema review is still required.

## Runtime and fixed isolation lab

`create_app()` now installs `Member2RuntimeAdapter`. Its protected preflight calls
`agentguard.platform.DockerLab.preflight(protected=True)`. Failed checks are stored
with the launch decision and shown by the dashboard. Even if all fixed probes pass,
no protected launcher currently exists; the adapter refuses instead of launching
an unrestricted process or falling back to a harness.

Authenticated owner routes:
- `GET /api/v1/platform`: actual host inventory and protected preflight.
- `POST /api/v1/tasks/{id}/isolation-lab`: empty body only; runs the upstream fixed
  lab against operator-configured `AG_LAB_IMAGE_ID=sha256:<64 hex>`. There is no image
  pull, caller-selected image/command/flags/mount, or promotion to business success.

Use a reviewed local image built with Member 2's original Dockerfile/runbook. The
API defaults to no configured lab image. On this Windows host it cannot run Linux
probes. Lab evidence is recorded separately and does not create a trusted binding.
Actual Docker execution/teardown still needs the supported Linux host and joint lab.

## Broker peer wiring on Linux

`Member2ChannelAuthorizer` reuses `agentguard.transport.PeerAuthorizer` on the real
socket connection. Before/after authorization it verifies a trusted cgroup inode,
process start ticks and the current application binding. It requires the launcher
to provide actual host PID start ticks and captured cgroup inode; never invent them.
The application cgroup ID can be opaque; the corresponding real cgroup path is a
separate operator/launcher input to the authorizer. PID, task ID and UID alone are
not authorization.

Start `application.broker_transport.serve_socket` in a trusted broker process with
`authorizer=...` and `capsule_uid=65532`. It checks the actual peer before and after
reading, rejects duplicate/non-finite JSON, bounds messages and validates the
current channel again in the broker. It creates a mode-600 socket and assigns only
the dedicated directory/socket to UID 65532 under a private host-owned parent.
Run the rootful/no-userns baseline only; other mappings remain unsupported.

Mount only that dedicated directory into the intended capsule. The protected
launcher must create/register the binding and arrange broker lifetime before any
agent code runs. Revoke on termination and verify descendants are gone. Host and
container mount/permission tests remain pending; fixture success is not OS proof.

## Tetragon capture forwarding

Run on the trusted Linux sensor host, using a sensor token from the operator-owned
registry outside the capsule. The token belongs in `AG_SENSOR_TOKEN`, never CLI
arguments or a capsule environment. Keep workload mapping and raw capture files
protected and outside capsule mounts. The mapping is a JSON array of the original
`agentguard.sensors.Workload` fields, issued by the trusted launcher.

```sh
python -m application.member2_exporter --input /protected/tetragon.jsonl --workloads /protected/workloads.json --sensor-id collector-01
```

This one-shot forwarder bounds frames, uses the original process normalizer, posts
only to `127.0.0.1:8000` with no proxies/redirects, and retains raw-record hashes as
references to the operator-retained source capture. The API independently verifies
source credentials and task/capsule/host/version mapping. Arguments are omitted by
the normalizer. Unsupported records, mapping failures and HTTP errors stop forwarding
without claiming health or coverage. Replays use stable source event identities.
It is not a tailing service, checkpoint manager, raw-transport authenticator, kernel
collector, or sensor-loss detector. EOF never means complete coverage.

## Output release and missing coverage

Protected reports are held until all required host process/file/connection and
network-flow scopes cover execution through the last trusted broker action. Windows
must be complete, gap/loss free and fresh (no more than five seconds old). This is
a scoped release precondition, not proof of future activity or a safety score.
TERE continues to assess the whole execution interval separately. Only registered
sources may submit coverage; parsing process records never creates coverage.

A held request keeps its immutable denial receipt. After genuine required coverage
arrives, retry using a fresh request ID. A duplicate request returns its prior
outcome and never writes a second report. The current Finance Agent stops on a
broker hold; an asynchronous wait/retry policy is future integration work.

## Remaining joint gates

1. Run the fixed Docker lab on the actual supported host and preserve results.
2. Implement protected workload creation/inspection/lifetime and register its real
   task/capsule/container/cgroup/process mapping before agent admission.
3. Test socket ownership, bind mounts, descendants, user namespaces, cross-capsule
   access and verified cleanup against real containers.
4. Install/pin actual Tetragon and implement continuous health, loss accounting,
   file/connect hooks and attributable network-flow capture. This forwarder alone
   cannot satisfy the required coverage scopes.
5. Run the approved real local model through the trusted broker inside the complete
   capsule workflow, then perform all S01–S16 and baseline comparisons.

No confidential data or external model/data transfer is enabled. The model remains
disabled by default. Production SSO, PostgreSQL/OS storage hardening and immutable
external evidence checkpoints also remain pending.
