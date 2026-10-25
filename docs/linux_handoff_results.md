# Linux implementation and live validation round

The newer [25 October Linux return round](linux_return_round.md) records the
application lifecycle, syscall-hook, packet and durable exporter follow-through.
This page retains the 24 October round and its original limitations below.

Owner: Member 2. Date: 24 October 2026. Start point: shared integration commit
`413d571de02d75b7c382a1bc87881147fc809281`.

This round adds and verifies real Linux building blocks. It does **not** finish the
full protected-agent MVP or promote the application's default readiness to true.

## Implemented and observed

- Installed Docker Engine from its official signed Ubuntu apt repository in the
  existing Ubuntu 26.04 WSL2 distribution. No Docker group access or TCP daemon
  endpoint was granted. Prerequisite certificate/curl packages were updated through
  signed Ubuntu packages. Reproducible setup is `platform/setup/install_docker.sh`.
- Resolved official Python and Tetragon images to immutable digests; verified the
  Tetragon signature against Cilium's release workflow, the GitHub OIDC issuer and
  transparency-log claims. `platform/versions.json` is the reviewed image selection;
  `linux/version_manifest.json` records actual deployed versions and images.
- The fixed isolation lab passed active UID/GID, no-new-privileges, seccomp,
  capabilities, filesystem, namespace/network, direct/child egress and local
  calculation checks. Cgroup/descendant termination was independently confirmed.
  Fixed one-file local log rotation by disabling compression, as required by the
  actual Docker version. Flags were inspected before image execution.
- Added `agentguard/capsules.py` and `agentguard/watchdog.py`: a fixed reviewed
  profile, exactly one private read-only broker directory, staged host admission,
  genuine process start ticks/cgroup inode, protected persistent records, a separate
  watchdog before start, monotonic/wall-clock/boot-aware deadlines and recovery.
  The watchdog can use the captured kernel `cgroup.kill` interface and confirms
  process exit plus channel revocation. Unknown identity is retained as Unverified.
- Two actual containers exercised the integrated application's real authority,
  broker and SO_PEERCRED/cgroup authorizer. Equal UID plus socket access did not
  authorize the wrong cgroup. Caller-chosen task fields were rejected. A raw-row
  output payload generated a genuine denied/blocked broker receipt. Real TERE
  findings retained both Blocked and missing-coverage Unverified outcomes.
- A live child was started before the parent exited; final cgroup emptiness was
  confirmed. A separate launcher request process deliberately exited with code 23;
  its detached watchdog still enforced the unadmitted capsule's short deadline.
  That test is specifically a pre-admission request failure, not a model attack.
- Tetragon's real base probes loaded and captured designated Python process/child
  exec/exit events, attributed using the actual container and captured cgroup inode.
  Captures are bounded, omit arguments and retain private raw references. Public
  artifacts omit host names and encoded parent IDs that can contain them.
- The integrated application runs from the real Linux host on loopback port 8000.
  Its database and distinct owner/runtime/integrity/sensor secrets remain in a
  root-private Linux directory, outside every capsule and Docker build context.

## Evidence and limits

| Artifact | Evidence |
|---|---|
| `linux/version_manifest.json` | Actual host/kernel/Docker/Python/image/signature state |
| `linux/host_capabilities.json` | Sanitized host inventory; generic audit entries are not automatically upgraded by separate experiments |
| `linux/live_lab_final.json` | Latest bounded real process experiment, original times, attribution and sampled metrics |
| `linux/live_lab_timestamp_gap.json` | Earlier real source-time conflict; kept separately rather than overwritten by a successful rerun |
| `linux/socket_lab.json` | Real peer/admission/containment checks, actual broker receipts and TERE findings |
| `linux/application_smoke.json` | Actual owner API creates a contract, runs the fixed Docker lab, then refuses protected launch without a binding |
| `linux/validation_windows.json`, `linux/validation_linux.json` | Reproducible combined regression/static-check summaries |
| `linux/dependency_audit.json` | Current locked Python advisory result; npm audit also reported zero known vulnerabilities |

The pinned sensor warned about the WSL procfs namespace inode and reported several
unsupported BPF features, including BPF LSM and syscall modify-return support. We
claim only the specific successfully captured base process probes. One exec event
had source time `2026-10-24T16:26:47.778417931Z` while its reported start time was
`2026-10-24T16:26:47.778418322Z`. The strict normalizer rejected the conflicting
ordering at its supported timestamp precision. This remains a compatibility issue
for joint review; no source times were repaired and no gate was relaxed to pass.

Observed ring-buffer/queue-loss and missing-process counters can be sampled, but
the export-failure metric family is absent in this configuration and remains null.
Sampling plus EOF is not continuous gap-free coverage. A later successful process
run does not erase the earlier gap or establish file/network coverage.

The socket test is deliberately a fixed non-model workload with a test-only trusted
admission callback. It exposes no provider credentials or protected raw payroll,
does not bypass the application's output coverage check, and never registers a
business-success result. The application default adapter still refuses protected
launch; staged admission is not connected to its complete sensor/lifecycle workflow.

The combined suite passes 122 tests and 13 subtests on Linux. Windows passes 118
tests and 13 subtests, with four Linux-specific skips. Lint, formatting, application
type checks and contract compatibility checks pass on both hosts. The retained
Starlette TestClient/httpx deprecation warning is a tooling follow-up; no dependency
or security gate was changed to suppress it.

## Reproduce on the owned Linux host

From a trusted clone, with the project's locked Python environment installed:

```sh
sudo sh platform/setup/install_docker.sh
sudo apt-get install cosign
sudo sh platform/setup/start_tetragon.sh

# Use the immutable base in platform/versions.json. Tags below name local outputs;
# tests take the actual immutable ID from docker image inspect, with no auto-pull.
docker build --build-arg PYTHON_BASE=docker.io/library/python@sha256:7dff173021016c8829ae58d5ce112ffc388073ebe67f351aeb6ba2909e35f847 -t agentguard-capsule:lab -f platform/profiles/Dockerfile .
docker build --build-arg PYTHON_BASE=docker.io/library/python@sha256:7dff173021016c8829ae58d5ce112ffc388073ebe67f351aeb6ba2909e35f847 -t agentguard-socket-lab:round1 -f platform/profiles/Dockerfile.socket-lab .
docker image inspect agentguard-capsule:lab agentguard-socket-lab:round1

python -m scripts.linux_live_lab --image-id sha256:<actual-local-lab-id>
python -m scripts.linux_socket_lab --image-id sha256:<actual-local-socket-id>
python -m scripts.integration_validate_round --label linux
python -m scripts.linux_version_manifest
python -m scripts.start_linux --lab-image-id sha256:<actual-local-lab-id>
```

Host-root execution is the reviewed initial mapping. Rootless/userns support is
still refused. Keep WSL active for long-running experiments; a distro shutdown can
stop background services. Neither the sensor nor capsules publish network ports.
The Dockerfile's missing-default-base warning is intentional: an explicit digest
is required. Runtime creation never pulls an image implicitly.

## Start/stop, diagnostics and recovery

Stop the loopback application with Ctrl+C. `docker stop agentguard-tetragon` stops
this project's sensor and removes its live coverage; restart through the verified
setup script. Keep raw captures, runtime records, database and credentials under
their private Linux directories. No committed artifact contains the actual secrets.

`StagedCapsules.recover()` re-establishes watchdogs after a trusted service restart;
it does not admit staged agents. Termination requires a captured cgroup identity
and confirmed empty/removed cgroup plus channel revocation. A bootstrap that exits
before identity capture stays Unverified; its stopped container/record is retained
for diagnosis. Failed experimental containers were not silently counted as passing.

Stopped lab containers are retained for inspection. Remove only specifically
identified project containers after reviewing their recorded IDs; do not prune
unrelated Docker state. No existing containers, host firewall rules or GPU drivers
were removed. System package removal/driver rollback is not automatic.

## S01–S16 state after this round

| ID | Current state |
|---|---|
| S01 | Pending actual model-driven protected report; real aggregate-only socket access works |
| S02 | Real restricted root/root-home checks pass; full selected-file sensor policy still pending |
| S03 | Real Python direct egress denied in fixed capsule |
| S04 | Real child Python egress denied; curl path still pending |
| S05 | Direct-IP case observed; DNS/UDP/alternate-protocol matrix pending |
| S06 | Real capsule raw-row output request denied by integrated broker |
| S07 | No real model call; Ollama/model/GPU setup not performed |
| S08 | Contract/expiry regressions pass; full end-to-end expiry/credential case pending |
| S09 | Real baseline profile gates and default protected refusal preserved |
| S10 | Unknown/reset metrics and strict gaps retained; continuous outage/hold experiment pending |
| S11 | Genuine process evidence available; full runtime/authorization matching still pending |
| S12 | Real blocked receipt + Unverified findings coexist; complete report recovery pending |
| S13 | Real same-UID different-cgroup socket access denied; broader stale/inherited-channel matrix pending |
| S14 | Real child/cgroup cleanup and detached pre-admission watchdog deadline verified |
| S15 | Fresh identities/private directories verified; full model/session restart acceptance pending |
| S16 | No baseline efficacy/performance comparison measured |

## Next joint gates

1. Review the genuine timestamp edge case against the pinned Tetragon semantics
   without repairing source evidence or silently weakening attribution.
2. Add supported file/connect policies, attributable network flow capture, durable
   continuous export, counter reset/export-failure accounting and coverage intervals.
3. Connect staged launch/admission, registered binding, socket service and verified
   completion to the application's lifecycle only after mandatory live sensor gates
   have real evidence. Preserve the four-field idempotent broker protocol.
4. Configure and measure the approved local model outside the capsule; run benign
   and injected inputs, all remaining S01–S16 cases and baseline comparisons.

Return branch: `main` unless repository protection requires a review branch. The
exact pushed commit is reported in the accompanying handoff message; `git log -1`
identifies the checkout being reviewed. No issue reply or teammate message is sent
automatically.
