# Integration status

Latest Linux return (25 October): [lifecycle and observer results](linux_return_round.md)
record genuine application/container, file/connect, packet and authenticated
export checks. Continuous coverage and protected model/report acceptance remain
open. Earlier rows below are historical checkpoints.

Recorded 24 October 2026. This file describes actual implementation and validation, not the target design.

Current application review (25 October): see
[the review fixes and next Linux tasks](application_review_round.md) and
`application_review_validation.json`. Source conflicts now hold admission/release,
model replies are bounded and strict, and admission decisions are invocation-local.
Complete continuous supervision and protected Finance acceptance remain pending.

Latest application update (25 October): see
[the lifecycle integration round](application_lifecycle_round.md) and its recorded
validation. The historical rows below describe earlier checkpoints. The staged
application workflow is now implemented; production admission and full live
monitoring/model acceptance remain blocked.

| Component | Code state | Validation state |
|---|---|---|
| Versioned task/event interfaces | Implemented | Strict validation/security regressions pass |
| Local Task Authority | Implemented | Signature, expiry, mutation and version tests pass |
| Synthetic Data Broker | Implemented | Aggregate-only and injection tests pass |
| Output Broker | Implemented | Raw rows/extra fields/incorrect totals denied; legitimate report succeeds |
| Model Broker | Interface implemented, provider absent | Template/budget tests use an explicitly injected test callable; no actual inference |
| SQLite evidence journal | Implemented | Append-only behavior, HMAC tamper detection, concurrent append and replay tests pass |
| TERE | Conservative first matcher | Four finding types, source trust, missing coverage and outcome independence tested |
| Local API/dashboard | Implemented | HTTP authentication/origin/routes tested; browser harness flow visually checked |
| Host capability audit | Implemented and run | Actual Windows report saved in `platform/docs/host_capabilities.json` |
| Linux Docker isolation lab | Adapter/image/probes authored | Command/profile/preflight/cgroup-path tests pass; **not run on Linux** |
| Per-capsule UDS | Peer/cgroup authorizer and server authored | proc identity parser tested; real Unix peer rejection test passed in WSL; two-container integration pending |
| Tetragon normalization | Process exec/exit adapter authored | Explicit fixture tests pass; **no live host evidence captured** |
| Tetragon file/connect hooks | Not implemented | Need actual supported host/version hooks and captured fixtures |
| Sensor export/health/coverage | Not implemented | No authenticated live stream or attested coverage intervals |
| Network flow collector | Not implemented | No packet/flow/content claims |
| Protected agent execution | Disabled | `/launch` returns readiness refusal; no agent/container starts |
| S01–S16 full MVP | Not complete | See `experiment_results.md` |

## Confirmed environment

Windows Python 3.14.2 and Node 24.13.0 are available. The workspace had no existing repository or code. Docker CLI was not on PATH. Initial sandboxed WSL queries returned `Wsl/E_ACCESSDENIED`; a later approved query found Ubuntu WSL2 and we started it for actual validation. Its kernel is 6.18.33.2-microsoft-standard-WSL2 with Python 3.14.4, cgroup v2 and BTF available. No Docker executable or Node is installed there. The full Python regression suite passed in WSL, including the real peer-credential test. Reports for both environments are under `platform/docs/`. No installation, kernel configuration, drivers or system services were changed.

The first sandboxed regression attempt could not use the default temporary directory; tests were corrected to use a workspace-local temporary root. Local HTTP tests then hit WinError 10013 in the network sandbox. Re-running the suite through the approved execution permission passed. These environment failures were not counted as successful tests.

## Next implementation gates

1. Run audit and fixed isolation lab on an owned supported Linux host; record effective inspect output, active probe results and cgroup termination evidence.
2. Capture real Tetragon process events; pin reviewed image digest, record kernel/sensor versions, test health/loss metrics and preserve authenticated raw references.
3. Integrate launcher-created per-capsule sockets before arbitrary agent code starts; prove peer identity and cross-capsule denial with two containers, including revoked/expired channels.
4. Implement continuous coverage intervals and output hold on sensor loss/export failure; add protected workload binding and conservative authorization matching.
5. Configure one approved real model provider outside the capsule with timeout/token/cost limits; run the payroll AI agent through all three brokers.
6. Complete S01–S16, adversarial tests, baselines and performance measurements before changing protected readiness to true.

## Integration update

The local `member1-integration` branch now joins the Member 1 application with
the existing platform/peer/sensor libraries. See `member2_integration.md` for exact
compatibility decisions, current routes and pending gates, and
`integration_validation.md` for the combined validation results. Protected execution
remains disabled; the original rows above describe the upstream snapshot. Its WSL
results describe Member 2's machine; this development host has no installed WSL or Docker.

The next Linux round and return-to-application workflow are assigned in
[Member 2 next steps](MEMBER_2_NEXT_STEPS.md).
# Latest Linux round

The preceding historical statuses describe the application checkpoint. The subsequent
real Linux platform work, exact evidence and remaining gates are recorded in
[`linux_handoff_results.md`](linux_handoff_results.md). The default protected
application runtime is still disabled; no live-model/full-coverage result is claimed.
