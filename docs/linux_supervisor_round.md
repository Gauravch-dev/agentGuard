# Continuous observer return round

Superseded for current implementation/results by the [Linux delivery return](linux_delivery_round.md).
The historical ten-pass recovery limit below is replaced by persistent bounded
retries, and process/hook subscriptions now start before bootstrap launch. Whole
coverage, packet attribution and source clock/loss acceptance remain blocked.

25 October 2026. Implements the Linux return work following application checkpoint
`4a9abea`. This is real Linux integration work, with the limits below retained.
It is not a completed protected Finance/S01–S16 acceptance round.

## Implemented

`agentguard/supervisor.py` manages continuous process, file/connect and independent
packet observers for each staged capsule. The application constructs it through
trusted host startup with `--continuous-observers`; this starts collectors, not an
approval override. Each source uses its separate registered credential and fixed
loopback ingestion routes. No credential or collector is placed in the capsule.

The supervisor tracks actual collector processes, Tetragon container epoch/image,
policy state, heartbeat freshness, wall/monotonic clock discontinuities, nullable
loss/export counters, resets, source gaps, queue backlog and export failures. It
rechecks workload process birth and cgroup inode. Individual metric series are
retained, so changed labels or decreasing counters cannot be hidden by summing.
Missing metrics stay unknown. Packet counters come from the actual AF_PACKET
socket; no packet payload or sender PID is fabricated.

Collectors have bounded lifetimes and journal/queue quotas. At most four capsules
are observed concurrently. An exited collector is retried at most three times;
its discontinuity and epoch change remain visible. Cancellation requests observer
shutdown without waiting for HTTP while holding the application store lock.
Collector teardown and exact managed-policy cleanup run outside that lock.

The durable queue now supports process/hook events, packet events and coverage on
three fixed authenticated API routes. Existing queues migrate without discarding
pending evidence, and migration requires the exclusive collector lease. A stored
route cannot redirect credentials to another endpoint. Startup replays preserved
journals/queues; it never resumes an old workload or restores its channel. Recovery
is bounded to 64 journals and ten retry passes; remaining backlog stays private
for another recovery attempt or investigation, without a completeness claim.

Two application integration changes were needed:

- Authenticated sensor ingestion receives its own bounded 10,000-request/minute
  budget per source and peer. Kernel traffic no longer consumes the owner's
  600-request/minute budget. Unknown/rotating credentials retain the ordinary
  budget; source authentication, host/origin, schema and body-size checks remain.
- Late durable source observations match their original unique registered capsule
  and contract version, even after a revision. Coverage uses that capsule's unique
  binding. Current admission, broker access, output and assessments still use the
  current revision. Historical contradictions remain scoped to the old revision.
  This fixes backlog rejection after revision without granting historical action
  rights or changing shared schemas.

The live reviewer uses bounded strict local registry/status reads with one shared
three-second acceptance deadline. Its assessment remains invocation-local; no
shared diagnostic state can approve a different capsule. The model provider keeps
the separate unchanged 30-second budget, fixed endpoint, digest checks and limits.

## Genuine results

Final validation: **191 Linux tests passed**, without skips; **176 Windows tests
passed**, with 15 Linux-specific skips. Thirteen subtests passed on each platform.
Lint, formatting, application types (20 source files), shared schema compatibility
and dashboard TypeScript/build passed. Locked Python advisory scanning found no
known vulnerabilities; no project data was submitted. The existing Starlette
TestClient/httpx deprecation warning remains.

The pulled checkpoint first passed all 180 Linux tests and 13 subtests, without
skips. The real hook → durable queue → authenticated application experiment passed
again against the stricter replay/metadata checks:
[`observer_pipeline_review.json`](linux/observer_pipeline_review.json).

The final real continuous experiment passed:
[`continuous_final_review.json`](linux/continuous_final_review.json). It verifies:

1. All three observer sources start, with actual process exec, file access,
   connection attempt and outgoing packet events delivered to the application.
2. Terminating only the exact lab packet helper causes a recorded restart, and
   genuine packet delivery resumes. The source discontinuity is not cleared.
3. Identical source details and coverage IDs replay as acknowledged duplicates.
   Deliberately altered replay/coverage claims return 409 and hold that revision.
4. The application can restart and replay an unchanged genuine packet frame after
   a labelled lost-ack fault injection, without duplicating the immutable event.
5. Cancellation verifies descendants/cgroup cleanup and channel revocation. A new
   authorized revision uses a fresh capsule and is not poisoned by old conflicts.
6. Partial/unknown windows never become complete, no Finance code is admitted,
   no broker/model action or report is created, and the evidence chain verifies.

The changed replay fields and restored queue delivery flag are explicitly labelled
negative protocol/transport inputs. They are not genuine loss telemetry or new
host effects; the genuine event payloads and immutable evidence are unchanged.

The refreshed real dashboard also starts all three sources with the final
pre-attachment PID/start/cgroup/namespace check, reports the bootstrap gap on
admission and verifies cancellation cleanup:
[`dashboard_observer_smoke.json`](linux/dashboard_observer_smoke.json).

The first experiment's observation check ran before the process stream caught up.
It is retained as [`continuous_review_initial.json`](linux/continuous_review_initial.json),
with its failed check. Private evidence subsequently contained all four event
classes. The corrected experiment waits for those actual classes; it does not
generate process records or repair timestamps to make the check pass.

The already approved Qwen2.5 model was warmed outside the capsule, then exercised
through the stricter actual local provider. Both benign and injected synthetic
inputs returned the authorized summary action with correct totals, in about 4.75
and 4.53 seconds:
[`model_review.json`](linux/model_review.json). These are two provider measurements,
not performance percentiles or an attack-prevention rate. They do not establish
an admitted Finance run, a blocked model exfiltration attempt or report release.

## Why protected admission still refuses

The supervisor is now connected and continuously observing. The following real
capability limits prevent it from certifying complete execution coverage:

| Reason | Meaning / required next change |
|---|---|
| `BOOTSTRAP_OBSERVATION_START_GAP` | Policies/subscriptions and packet tap attach after bootstrap birth. Design and verify observation that covers the initial interval; do not backdate a later healthy sample. |
| `FILE_AND_NETWORK_HOOK_SCOPE_PARTIAL` | Listed syscall hooks do not cover every possible file/network mechanism, including the outstanding inherited-FD/mmap/io_uring/curl matrix. Expand and validate the supported scope. |
| `NETWORK_PROCESS_ATTRIBUTION_UNAVAILABLE` | AF_PACKET proves namespace traffic, not the sender's process birth. The exported event leaves process identity absent, and TERE retains Unverified. A trusted process/cgroup flow join still needs implementation/review. |
| `SOURCE_CLOCK_SEMANTICS_UNVERIFIED` | The earlier genuine source timestamp conflict remains unresolved. Wall/monotonic checks do not repair or certify that separate source-clock issue. |
| Unknown host loss accounting | Some pinned-sensor metric families, including the export-failure counter, are absent. They stay null/unknown; sampled zeros in other counters do not substitute for them. |

The existing v1 coverage wire has a non-null integer `lost_events`. Where loss is
unknown, the count is its schema default and the window status is **unknown**,
not complete. The separate supervisor metric snapshot preserves the null value;
zero must not be read as measured zero loss in such a window.

The supervisor deliberately emits partial, unknown or unavailable windows for
this baseline. Complete coverage is not inferred from EOF, a running helper, a
successful export, an empty queue or these passing experiments. Because the
mandatory admission gates remain unsatisfied, admitted benign/injected Finance
runs, genuine complete-coverage report continuation and full S01–S16/baseline
comparisons remain blocked. No fixture reviewer or coverage bypass was used.

## Reproduce and operate

On the existing trusted rootful Ubuntu host, from the repository root:

```sh
source /var/lib/agentguard/venv/bin/activate
sh platform/setup/start_tetragon.sh
systemctl start agentguard-model
python -m scripts.linux_sensor_registry
finance_image=$(docker image inspect --format '{{.Id}}' agentguard-finance:round2)
model_digest=$(python -c 'import json; print(json.load(open("platform/versions.json"))["approved_model_digest"])')

python -m scripts.linux_observer_pipeline_lab --image-id "$finance_image" --output docs/linux/observer_pipeline_review.json
python -m scripts.linux_continuous_lab --image-id "$finance_image" --approved-model-digest "$model_digest" --output docs/linux/continuous_final_review.json
python -m scripts.integration_validate_round --label linux

python -m scripts.start_linux --staged-image-id "$finance_image" \
  --sensor-registry /var/lib/agentguard/control/sensors.json \
  --approved-model-digest "$model_digest" --continuous-observers
```

Run one control-plane server on port 8000. Keep WSL active. A current model digest
must match the approved value, and a live reviewer may report that the model needs
warming after idle unload. The model-only lab is available for approved synthetic
provider checks; do not extend its acceptance budget to hide a timeout.

Private observer manifests, source journals, health records, checkpoints, queues
and pending recovery diagnostics stay under the selected control state's
`observers/` directory. Stop the server with Ctrl+C; it revokes/contains workloads
and requests observer cleanup. Stopped containers and private evidence remain for
diagnosis. There is no broad Docker prune or automatic evidence deletion.

## Return to application review

Review the authenticated ingestion quotas, historical source-binding lookup,
bounded reviewer reads and asynchronous observer lifecycle against the live
evidence. Keep current-revision conflict gates and output verification intact.
The next platform work is the pre-birth observation strategy, broader supported
hooks, trustworthy packet/process attribution and source-clock/loss semantics;
then genuinely complete coverage and protected Finance acceptance can be tested.

Metric meaning follows the official [Tetragon metric reference](https://tetragon.io/docs/reference/metrics/)
and [event-stream documentation](https://tetragon.io/docs/concepts/events/).
