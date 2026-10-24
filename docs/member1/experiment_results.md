# Validation results â€” 24 October 2026

Environment: Windows control-plane development, Python 3.12.14, Node 24.21.0.
Tests use pytest 9.1.1; the Linux transport is type-checked for the Linux deployment
target but has not run against actual Linux peer credentials or sensors.

| Check | Result | Scope / limits |
|---|---|---|
| Unit, contract, application integration | 45 passed | Model/runtime doubles and generated events are tests only |
| Exact shared handoff examples | Passed | Original task/event JSON examples validate against generated schemas |
| Shared handoff equality | Passed | Shared contract text is identical in both original files |
| Schema drift check | Passed | Generated JSON matches checked-in schemas |
| Ruff lint/security rules | Passed | Authored Python source and tests |
| Ruff formatting | Passed | Authored source files |
| Mypy | Passed, 14 source files | Linux deployment target; Windows API behavior separately tested |
| Dashboard TypeScript and Vite build | Passed | Production assets generated; no external fonts/assets |
| Dashboard dependency advisory scan | 0 known advisories | npm audit, including development dependencies |
| Python dependency advisory scan | 0 known advisories | pip-audit / OSV, 59 exact package versions match final lock; report saved alongside this file |
| Source secret scan | 0 potential secrets | detect-secrets, verification disabled; excludes third-party dependencies, lockfile hashes, caches and original handoffs |
| Real API smoke | Passed | Auth, reviewed template, fail-closed launch, result, revision and static UI serving |

One non-failing dependency warning: current Starlette TestClient deprecates its
httpx integration in favor of httpx2. Application HTTP behavior is tested; this is
not an authorization or output-validation failure.

Security regression checks include forged task/channel context, strict report
fields and math, replay conflicts, revoked versions, expired/tampered contracts,
append-only storage, corrupted-evidence refusal, duplicate observations, clock
skew, missing/lost coverage, PID/cgroup attribution failure, model errors/oversize/
redirects, unverified termination and plural business/security outcomes. A borrowed
broker correlation ID does not authorize an otherwise unexplained network effect.

No actual model execution, Linux network/file prevention, Tetragon/flow capture,
GPU benchmark, true cross-capsule socket test, descendant teardown proof or baseline
comparison was performed. No confidential payroll data or external model/data
transfer was used. Dependency advisory queries sent package names/versions only.
Passing application tests does not constitute joint S01â€“S16 security-lab acceptance.
