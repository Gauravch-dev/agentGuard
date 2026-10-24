# Implementation status — 24 October 2026

This is the Member 1 application prototype in the active development workspace. Original
handoffs are preserved. Shared schemas and additional envelopes are proposed for
Member 2 review, not jointly signed off. No confidential data or external model
transfer is enabled.

| Area | Implemented | Pending validation/integration |
|---|---|---|
| A1 Authority | Reviewed Finance template, authenticated owner, signed immutable versions, expiry, lifecycle audit, terminal-only revision | Production SSO/RBAC; independent approval workflow |
| A2 Finance Agent | Synthetic payroll, real model-driven tool-choice code, benign/injected lab documents, broker-only client | Actual local model run inside a Linux capsule |
| A3 Data | Fixed aggregate operation, strict payload, task-bound channel, denial receipts | Linux peer resolver and cross-capsule mount tests |
| A4 Model | Disabled default; fixed loopback provider/model/template, canonical aggregate verification, limits, no provider keys in agent | Installed local model, real response/usage evidence |
| A5 Output | Exact report schema, decimal totals verified, no prose/extra keys/recipient, one internal release per capsule | Joint live report run |
| A6 API/storage | Owner/runtime/sensor credentials separated; host/source registry, body/rate bounds, SQLite append-only ledger, HMAC chain, receipt time, dedup, notes | PostgreSQL/OS ACL deployment, external log checkpoint, sustained load |
| A7 TERE | Pure service, plural findings, coverage intervals/classes/loss, attribution, skew/duplicates, independent business outcome | Real host/network evidence correlation and baseline experiment |
| A8 Dashboard | React API-backed contracts/readiness/evidence/findings/report, no optimistic isolation badge | Joint live demonstration |

Runtime and model doubles occur only in `tests/`. Any generated sensor observations
are test data. They do not establish actual Linux prevention, process capture,
network observability, credential isolation or absence of inherited task state.
`UnavailableRuntime` refuses launch; no live simulation mode exists.

## Shared acceptance matrix

| ID | Application coverage | Joint acceptance |
|---|---|---|
| S01 | Internal report tested using deterministic model/runtime doubles | Pending real model + capsule |
| S02 | Can ingest/reconcile policy denial; no OS enforcement implemented | Pending Linux forbidden read |
| S03 | Unknown flow/attempt semantics tested | Pending actual Python HTTP/HTTPS denial |
| S04 | Channel protocol independent of agent-selected task identity | Pending curl/descendant enforcement |
| S05 | No arbitrary broker URL accepted | Pending DNS/IP/protocol lab |
| S06 | Raw rows/extra output fields rejected and receipted | Application verified; joint pending |
| S07 | Local model adapter and disabled-failure behavior tested | Pending actual model/credential isolation |
| S08 | Expiry/tampering prevents authority/broker/launch access | Application verified; joint pending |
| S09 | Missing runtime/readiness refuses launch without fallback | Application verified; real preflight pending |
| S10 | Coverage loss/missing intervals produce Unverified | Application verified on fixtures; sensor-stop lab pending |
| S11 | Attributable unknown effect becomes Unexplained, no content inference | Application verified on fixtures; collector pending |
| S12 | Completed business result retains blocked and coverage findings | Application verified with doubles; joint pending |
| S13 | Forged/cross-task context rejected; revoked versions cannot use channel | Linux socket/user-namespace tests pending |
| S14 | Request alone cannot mark terminated; inspection/descendant proof required | Real process/cgroup teardown pending |
| S15 | Terminal revision requires fresh capsule/channel; prior channel revoked | Fresh OS filesystem/env/memory lab pending |
| S16 | No invented efficacy/novelty numbers | All baseline experiments pending |

Automated validation results and their limits are recorded in `experiment_results.md`.
The MVP as a whole is **not complete** until Member 2 and actual model runs supply
the outstanding evidence. App-level passing tests must not be presented as S01–S16
Linux security-lab passes.
