# Acceptance matrix and measured results

24 October 2026. No attack-success, performance, false-positive, latency or overhead numbers have been measured. Unit tests and an authenticated local harness are not full Linux acceptance tests.

| ID | Scenario | Current evidence | Full MVP state |
|---|---|---|---|
| S01 | Approved summary | Real synthetic broker workflow saves correct aggregates locally | Partial: no AI capsule |
| S02 | Forbidden file read | Fixed Linux probe authored; effective mount/profile validation unit-tested | Pending Linux |
| S03 | Python direct egress | Network-none builder/inspection tests; active probe authored | Pending Linux |
| S04 | Child/curl attempt | Child Python probe authored; curl path absent | Pending Linux |
| S05 | DNS/direct-IP/protocol bypass | Direct-IP probe authored; DNS/UDP suite absent | Pending Linux |
| S06 | Raw rows to approved output | Broker rejection tested; no report persisted | Application gate passed |
| S07 | Approved real model call | Callable/template/budget interface tests only; provider not configured | Pending |
| S08 | Invalid/expired contract | Authority and broker refusal tests pass | Application gate passed; runtime Linux pending |
| S09 | Readiness failure | Test proves no Docker command on failed preflight; API refuses `/launch` | Application gate passed; effective Linux controls pending |
| S10 | Sensor loss/drop | Missing coverage yields Unverified; protected output hook refuses | Partial: actual collector outage untested |
| S11 | Unknown attributable effect | Explicit sensor-shaped fixtures yield Unexplained | Partial: no live observation |
| S12 | Complete after blocked operation | Actual harness returns business completed + Blocked + Unverified + scoped Aligned | Application gate passed; AI/Linux pending |
| S13 | Cross-capsule misuse | Request task spoofing rejected; Linux peer code and test authored | Pending two Linux capsules |
| S14 | Termination confirmation | Captured cgroup required; no-cgroup refusal tested | Pending Linux descendants |
| S15 | Fresh capsule/revocation | Fresh harness IDs and revoked broker session tests pass | Pending runtime cleanup/credential checks |
| S16 | Baseline comparison | No experiments run | Pending |

## Validation record

The Windows automated run completed 51 tests: 50 passed and one Linux-only SO_PEERCRED test was skipped. The same suite ran in the installed Ubuntu WSL2 distribution: all 51 passed, including a real socket peer-credential rejection test. This still does not establish container peer/mount isolation. See `validation.json` and `validation-wsl.json` for recorded counts. Tests cover contract signatures/expiry, broker schema/scope/data minimization/budgets, concurrent evidence integrity/replay/tampering, reconciliation trust rules, sensor attribution fixtures, runtime profile/preflight and authenticated HTTP behavior.

JavaScript syntax was checked with `node --check dashboard/app.js`; Python source was compiled with `compileall`. The dashboard was opened in the in-app browser, authenticated, and the policy-harness button completed a new real local broker run. Its visible result showed business Completed, one enforcement denial, independent coverage Unverified and a verified local evidence chain. A screenshot is saved in `screenshots/dashboard.png`.

This does not establish container, eBPF, network-flow, provider or cross-capsule effectiveness. Sensor fixtures in tests are test input and are never stored as real host observations in demo runs.
