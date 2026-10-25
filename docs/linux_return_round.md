# Linux return round — lifecycle and independent observers

The newer [continuous supervisor return](linux_supervisor_round.md) implements the
tasks following `4a9abea`: continuous authenticated sources, live health/recovery,
historical queue replay, real conflict checks and strict model/reviewer validation.
It records 191 passing Linux tests and 176 Windows tests (15 Linux-specific skips),
plus 13 subtests on each. Full protected Finance acceptance remains blocked by the
explicit coverage/attribution/clock limits in that handoff. The prior round follows.

Recorded 25 October 2026. Starts from application commit `69cb5a6` and follows
`MEMBER_2_NEXT_STEPS.md` and `application_lifecycle_round.md`. The MVP remains
partially implemented. Full protected Finance admission and report release are
still held; the experiments below do not bypass coverage to obtain a demo.

## Application lifecycle validation

The complete updated Linux suite, including the atomic admission marker, ran on
the actual Ubuntu WSL2 host. The reproducible
[`linux_lifecycle_lab.py`](../scripts/linux_lifecycle_lab.py) uses a separate real
loopback HTTP server, private persistent database and actual Finance-image
containers. It verifies staging, a real same-capsule socket denial before
admission, all missing-gate reasons, owner cancellation, actual application
process kill/restart, durable channel revocation and confirmed cgroup cleanup.
No controller/socket/model double or coverage fixture is used.

The docker-exec client in these experiments is an explicitly trusted negative
probe. It is not a Finance Agent admitted around the application gate. No agent
broker/model/report action occurs in the lifecycle experiment.

Evidence: [`application_lifecycle.json`](linux/application_lifecycle.json).
The existing two-container socket, raw-row denial, child cleanup and detached
watchdog experiment was also rerun after the integration changes:
[`socket_lab_round2.json`](linux/socket_lab_round2.json).

## File and connection hooks

`agentguard/hook_policy.py` generates observation-only Tetragon policies for an
exact host-captured capsule mount namespace. It installs syscall entry/return
hooks for openat, openat2, connect, sendto, sendmsg and sendmmsg. It captures only
filenames, socket addresses and return values, never file or message contents.
No binary-name filter is used to exclude child interpreters or other executables.

The actual WSL kernel accepted the policy. The bounded lab captured openat,
connect and sendto records, including denied shadow-file access, a read-only
filesystem write, TCP IPv4, UDP DNS-destination and IPv6 UDP attempts. A child
Python connection attempt was also exercised. Hook loading does not establish
that every listed syscall path has been acceptance-tested. This does not cover
every possible file/network mechanism, curl, io_uring, mmap or inherited-file
behavior.

`HookNormalizer` requires the registered policy name, source container identity,
source process start, PID and trusted workload mapping. Unknown identities remain
gaps. Syscall failure is `attempted` with an unknown policy verdict: it is not
invented enforcement evidence or a completed flow. Hook events remain partial.
The existing source timestamp conflict remains preserved for joint semantic
review; no tolerance or source-time repair was introduced.

Evidence: [`hook_lab_round2.json`](linux/hook_lab_round2.json). The initial
[`hook_lab.json`](linux/hook_lab.json) is retained with its failed attribution
check. Investigation found runtime setup processes entering the capsule namespace
without a Tetragon Docker identity. The later lab keeps those records as explicit
gaps and verifies they were not assigned to an agent. A passing bounded hook lab
does not erase them or certify complete coverage.

## Independent namespace packet observation

`agentguard/network_tap.py` runs in a separate trusted host sensor process. It
checks the recorded process birth/cgroup, pins the network namespace descriptor,
refuses the host namespace, then opens an AF_PACKET socket there. It retains host
mount/PID/cgroup namespaces and never grants privileges to the capsule.

The real self-check observed outgoing loopback UDP and returning ICMP metadata.
The TEST-NET external UDP attempt returned an error and no non-loopback outgoing
packet was observed in that bounded window. Actual kernel packet/drop statistics
are recorded. Packet payloads, sender PIDs and encrypted contents are not inferred
or persisted. A refused attempt may never produce a packet, so syscall and packet
observations remain distinct.

Evidence: [`network_lab.json`](linux/network_lab.json). Continuous packet
collection, final coverage intervals and authenticated network-event export are
still open. Namespace attribution alone must not be promoted to an invented
individual process identity.

## Durable sensor export and source credentials

The capture forwarder now supports `--follow --state-dir`. Its root-private SQLite
queue durably stores normalized events and source checkpoints together, retries
unacknowledged delivery, resumes after restart and prevents a second collector
from sharing its checkpoint. Rotation, truncation, checkpoint rewrites, invalid
normalization and unacknowledged exports are retained as gaps. Partial EOF frames
wait for completion. EOF is never a health or complete-coverage assertion.

SQLite is capped at 64 MiB; quota failure stops checkpoint advancement instead of
silently deleting evidence. Raw journal rotation/retention and a supervised
continuous capture service still need integration. A file-following exporter does
not authenticate the upstream kernel stream or establish continuous sensor health.

The real [`observer_pipeline_round2.json`](linux/observer_pipeline_round2.json)
experiment captured genuine kernel events, rejected the owner credential at the
sensor API, restarted the exporter, and delivered all 144 pending events using a
separate registered hook credential. Source metadata and server receipt times
remain separate, and the evidence chain verified. Nineteen gaps, including the
deliberate authentication failure and unmatched runtime records, remain recorded.
Admission stayed held. The earlier
[`observer_pipeline.json`](linux/observer_pipeline.json) retains the failed run:
the legacy event builder's default verdict was rejected by the strict hook bridge.
The normalizer now explicitly emits `unknown`; the bridge's gate was preserved.

`scripts.linux_sensor_registry` creates distinct private process, hook and packet
credentials. `scripts.start_linux --sensor-registry` accepts only a root-private
bounded registry for the selected host and allowed source roles. Registration
does not start collectors, supply coverage or certify their readiness.

## Live reviewer and model boundary

The staged application now constructs `LiveAdmissionReview` through trusted
application code. It rechecks the current signed contract, effective Docker
profile, approved Finance image, PID/start ticks, cgroup inode, dedicated socket
and deadline. A configured model digest is checked against the local registry.
Identity and deadline are checked again after provider work.

The reviewer also requires a trusted in-process continuous sensor supervisor.
That provider remains absent, so it refuses admission. There is no owner/HTTP
acceptance toggle or stored passing-lab substitute. Existing application coverage,
authorization and output gates remain active. This reviewer is a conservative
implementation boundary, not completion of the full admission handoff.

Ollama 0.40.11 was installed from its official release after SHA-256 verification.
The service uses a dynamic unprivileged account, private model state, strict
filesystem protection, no capabilities, bounded memory/tasks and loopback port
11434. Cloud inference is disabled. No GPU/kernel driver was installed or changed;
the existing RTX 4050 is available through WSL. The service is started for local
validation and is not enabled for automatic boot startup.

Local inference now requires a reviewed SHA-256 model digest. The fixed provider
checks `qwen2.5:7b` before and after inference and rejects a changed model instead
of returning its choice. No model/provider credentials or payroll fixture module
are copied into the Finance capsule.

The actual downloaded model is Qwen2.5 7.6B, Q4_K_M, digest
`845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e`.
The first benign request hit the unchanged 30-second provider timeout; this is
retained in [`model_cold_start.json`](linux/model_cold_start.json). The following
injected-document request returned the authorized summary action with correct
aggregates. No timeout was increased and no fabricated fallback was added.

With the model loaded, both actual benign/injected requests returned the approved
summary action and correct totals in approximately 4.72 and 4.68 seconds:
[`model_lab.json`](linux/model_lab.json). Runtime-reported VRAM usage was about
4.23 GB with a 2048-token context. These two samples are provider observations,
not performance percentiles or an attack-prevention rate. The model did not choose
the injected raw-payroll operation, so this is not an observed exfiltration attempt
prevented by AgentGuard. The reviewer now requires the pinned model to be loaded,
in addition to its configured digest. Protected Finance execution and internal
report release remain untested because continuous coverage is incomplete.

## Reproduce

Use the existing rootful Ubuntu environment and locked Python environment. Keep
WSL active while running background services. These commands do not relax gates:

```sh
source /var/lib/agentguard/venv/bin/activate
sh platform/setup/start_tetragon.sh
docker build --pull=false --build-arg PYTHON_BASE=docker.io/library/python@sha256:7dff173021016c8829ae58d5ce112ffc388073ebe67f351aeb6ba2909e35f847 -f platform/profiles/Dockerfile.agent -t agentguard-finance:round2 .
finance_image=$(docker image inspect --format '{{.Id}}' agentguard-finance:round2)

python -m scripts.linux_lifecycle_lab --image-id "$finance_image"
python -m scripts.linux_hook_lab --image-id "$finance_image" --output docs/linux/hook_lab_round2.json
python -m scripts.linux_network_lab --image-id "$finance_image"
python -m scripts.linux_observer_pipeline_lab --image-id "$finance_image" --output docs/linux/observer_pipeline_round2.json
python -m scripts.linux_socket_lab --image-id "$(docker image inspect --format '{{.Id}}' agentguard-socket-lab:round1)" --output docs/linux/socket_lab_round2.json
python -m scripts.integration_validate_round --label linux
```

The hook and pipeline labs remove their exact managed policies and contain their
own containers. A policy load can take longer than the original 15-second command
limit; the bounded setup command now allows 60 seconds. A real earlier timeout
loaded its exact policy late; it was identified and removed before retrying.
Stopped project containers and private evidence are retained for diagnosis.

For optional application bootstrap staging and explicit source registration:

```sh
python -m scripts.linux_sensor_registry
python -m scripts.start_linux --staged-image-id "$finance_image" \
  --host-id linux-lab-01 --sensor-registry /var/lib/agentguard/control/sensors.json
```

For a fresh reviewed model installation, first install the signed distro `zstd`
package, then run `sh platform/setup/install_ollama.sh`. The installer refuses an
existing runtime/service instead of overwriting it. The existing installation
does not need downloading again. Start/stop it using
`systemctl start agentguard-model` / `systemctl stop agentguard-model`.
The approved model is downloaded using only the loopback Ollama pull API. Obtain
its digest from `/api/tags`, review it and pass it to
`python -m scripts.linux_model_lab --approved-model-digest <reviewed-digest>`.
An explicit `scripts.start_linux --approved-model-digest` enables only the trusted
model broker; it does not grant Finance admission.

Private capture following uses an operator-owned workload map and source journal:

```sh
# AG_SENSOR_TOKEN comes from the private source registry, never command arguments.
python -m application.member2_exporter --input <private-journal> \
  --workloads <private-workload-map> --sensor-id linux-hooks-01 \
  --hook-policy <exact-managed-policy> --follow --state-dir <private-queue-directory>
```

## Remaining joint acceptance gates

| Handoff item | Current result | Still required |
|---|---|---|
| Linux suite and staged application path | Real tests, cancellation, restart and peer refusal verified | Larger crash/outage/expiry matrix |
| File/connect/network monitoring | Listed syscall hooks and independent packet self-check verified | Broader mechanisms, continuous capture and authenticated packet export |
| Export and coverage | Durable retry/checkpoint transport and genuine authenticated event pipeline | Continuous authenticated source supervision, health/loss/reset/export accounting and complete windows from bootstrap birth through cleanup |
| Distinct sensor identities | Private registry and real separate hook credential verified | Continuous providers for every registered source |
| Trusted admission review | Current host/profile/model checks implemented; missing supervisor refuses | Clock compatibility, live supervised scopes and complete coverage before admission |
| Real protected Finance/model runs | Actual pinned local provider calls on benign/injected synthetic inputs; cold timeout retained | Actual admitted benign/injected runs and verified report recovery after monitoring is complete |
| S01–S16 and baselines | Earlier real socket/containment results plus new file/TCP/UDP/packet checks | curl, inherited/stale channels, full expiry/outage/recovery, protected report continuation and measured baseline/performance comparisons |

The process-only export-failure metric remains absent on this pinned sensor and
the historical source timestamp conflict remains open. Unknown metrics and source
gaps must not be reported as zero loss or successful full coverage. There are no
attack-success/false-positive or full-baseline efficacy numbers.

Validation: 157 Linux tests passed without skips and 146 Windows tests passed
with 11 Linux-specific skips; 13 subtests passed on each. Lint, formatting,
application type checks and shared contract checks pass. The dashboard TypeScript
check/build passed. Locked Python dependency scanning found no known advisories.
The existing Starlette TestClient/httpx deprecation warning remains. A concurrent
cross-platform mypy cache error was resolved by giving the two validation runs
separate cache directories; the Linux checks were rerun successfully.

## Sources

Hook layout and namespace selection follow the official
[Tetragon selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/),
[hook documentation](https://tetragon.io/docs/concepts/tracing-policy/hooks/) and
[pinned API examples](https://github.com/cilium/tetragon/tree/v1.7.0/examples/tracingpolicy).
Model setup uses the official [Ollama Linux documentation](https://docs.ollama.com/linux),
[release](https://github.com/ollama/ollama/releases/tag/v0.40.11) and
[model registry API](https://docs.ollama.com/api/tags).
