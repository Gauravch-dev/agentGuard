# Integrated validation — 24 October 2026

Base: Member 2 commit `198aea6515954130ed58ed21601a23be767596a0`.
Environment: Windows, Python 3.12.14, Node 24.21.0. The current host does not have
installed WSL or Docker. Upstream WSL reports describe Member 2's separate host.

| Check | Result | Scope |
|---|---|---|
| Combined pytest suite | 115 passed, 1 skipped; 13 subtests passed | Both original suites plus 20 new integration cases |
| Skipped test | Real Linux SO_PEERCRED rejection | Requires Linux /proc/cgroups; not counted as passed |
| JSON Schema and handoff compatibility | Passed | Exact shared handoff examples; unchanged original core fields/enums |
| Schema drift | Passed | Includes explicit Member 2 extension envelope |
| Ruff lint and formatting | Passed | Authored Member 1/integration code; upstream source kept unchanged |
| Mypy | Passed, 17 source files | Linux deployment target; upstream untyped modules excluded from type assertions |
| React TypeScript + Vite | Passed | Production build in dashboard/application/dist |
| Dashboard dependency scan | Zero known advisories | Current lockfile; npm audit |
| Application/dev Python dependencies | Zero known advisories | All 59 versions exactly match the previously scanned lock |
| Build dependency scan | Zero known advisories | Updated setuptools 84.1.0, scanned separately with pip-audit/OSV |
| Source secret scan | Zero potential secrets after review | Commit SHA explicitly allowlisted as a non-secret; dependencies, runtime state, build assets and archival documents excluded |
| Host inventory | Executed read-only | docs/integration_host_capabilities.json |

One non-failing Starlette TestClient/httpx deprecation warning remains. It does not
indicate a failed authorization test. Package wheel-building was not performed.

New tests cover mutual task-contract validation, authenticated Member 2 process
normalization and metadata separation, replay handling, rejection of forged source
metadata and harness records, strict JSON, protected launch refusal despite passing
fixed-probe test doubles, owner-only preflight, fixed-lab input restrictions,
coverage holds/freshness/loss and authenticated release, cgroup inode/process-birth/
revocation checks on fixtures, fixed-local capture forwarding, invalid source
shapes, and refusing a report based on the other workbench's different payroll.

No Docker image was run or pulled, sensor installed, real model called, or genuine
container networking/file restriction measured here. The capture forwarder was
tested with a mocked local HTTP transport; no source fixture is claimed as live
telemetry. The protected launcher is still missing and remains disabled even when
fixed probes report success. Passing these tests is not S01–S16 joint acceptance.

Member 2's executable platform/sensor/legacy application source, two upstream test files,
and legacy JSON Schemas are unchanged. A host-capability note was cleaned of tool-specific wording. Their existing unit tests pass in the
combined suite. No confidential payroll or external model transfer was used.
Only source/dependency downloads and package advisory queries used the network.
