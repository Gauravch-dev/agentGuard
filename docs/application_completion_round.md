# Member 1 implementation completion and Linux return

Recorded 25 October 2026. Reviewed upstream:
`5c5c79bcee65508d36e7add94ec4b2ffce5c497e`.

The Member 1 MVP application implementation is complete for the agreed local,
single-worker prototype. Its final joint acceptance is still open: the current
Linux sensors cannot establish mandatory complete coverage, so protected Finance
admission and a full S01–S16 demonstration remain held. Application test doubles
are simulations and never count as Linux/model acceptance evidence.

## Deliverables against the original Member 1 handoff

| Item | Implemented application behavior | Evidence / remaining acceptance |
|---|---|---|
| A1 Task Authority | Reviewed Finance template, authenticated approval, signed immutable contracts, expiry, lifecycle, serialized terminal-only revisions | Authority, API and revision regressions pass; historical reads cannot restore broker authority. |
| A2 Finance Agent | Broker-only Python tool loop, synthetic payroll, benign/injected documents, bounded retry on coverage holds | Agent tests pass. Member 2 has genuine warmed provider results; the admitted capsule-to-model-to-report run still requires complete monitoring. |
| A3 Data Broker | Fixed aggregate-only operation, task/channel binding, strict payload and denial receipts | Application allow/deny tests pass; real platform peer tests remain Member 2's responsibility. |
| A4 Model Broker | Fixed loopback provider/model, approved digest checks, canonical aggregate payload, strict bounded replies, deadline and budgets | Parser/failure/authorization tests pass. No external provider or confidential data is enabled. |
| A5 Output Broker | Independently checked totals, exact typed report, internal-only destination, atomic report/release receipt | Raw rows, extra fields, incorrect totals and uncertain coverage are denied. Actual admitted report release remains pending. |
| A6 API / evidence | Separate owner/runtime/sensor credentials, authenticated provenance, immutable sequenced SQLite ledger, HMAC verification, conflicts, review notes and request bounds | Integration tests pass. SQLite is the documented MVP persistence choice; OS file protection belongs to deployment. |
| A7 Reconciliation | Separate business outcome and plural Aligned/Blocked/Unexplained/Unverified findings; scope/identity/time/coverage checks, source conflicts and evidence references | Unit, contract and integration tests pass. Full live S01–S16 and baseline comparisons still need Linux artifacts. |
| A8 Dashboard | Real backend task/status/report/findings, historical revisions, filtered/paged evidence, source health/loss, last receipt, review notes | Type/build and synthetic browser checks pass. No UI action grants admission or invents an enforcement result. |

## Changes in this final application round

- Owner views select a signed contract revision and its binding, readiness,
  receipts, report, findings, notes and evidence. Late durable ingestion validates
  the signature of the historical revision as well as its immutable mapping.
- Concurrent revision approval is serialized. An old revision can be inspected
  and annotated but never becomes the active broker authority again.
- The monitoring view checks capsule/cgroup identity and exposes only bounded
  source counters, heartbeat age and reason codes. Unknown loss stays unknown;
  private observer paths, credentials and raw diagnostic objects are excluded.
  This diagnostic view cannot grant protected execution readiness.
- Owner polling does not rerun the live Docker/model admission reviewer. The
  explicit admission request still performs that review and all existing gates.
- Verified natural process exit signals the observer to drain without waiting
  for its HTTP delivery under the evidence lock. Late final coverage remains
  accepted while the broker stays revoked. Shutdown attempts every task and both
  socket/observer cleanup, including when another cleanup step fails.
- Authenticated owner/runtime/sensor quotas are separate from invalid callers.
  The bounded request limiter reclaims idle buckets instead of exhausting its
  permanent bucket table. Single-worker operation remains required.
- Dashboard reads use a consistent selected revision, serialize periodic refresh,
  reject stale responses after switching views, pause polling during inspection
  or note entry, and escape note text. Historical execution controls are disabled.

Shared task/event/coverage schemas and the four-field broker envelope are
unchanged. These read APIs add no source privileges or new admission shortcuts.

## Owner API additions and operation

All routes below require the owner credential. Runtime and sensor credentials
cannot read them. The server remains loopback-only.

| Request | Behavior |
|---|---|
| `GET /api/v1/tasks/{id}/revisions` | Versions and lifecycle times, newest first |
| `GET /api/v1/tasks/{id}?version=1` | Selected contract, binding and execution view; returns `current_version` and `is_current` |
| `GET /api/v1/tasks/{id}/result?version=1` | Reconciled historical outcome and retained internal report |
| `GET /api/v1/tasks/{id}/posture?version=1` | Coverage summary; live source snapshot only for the current version |
| `GET /api/v1/tasks/{id}/notes?version=1` | Append-only review notes for the selected revision |
| `POST /api/v1/tasks/{id}/notes?version=1` | Record a typed plain-text review note; cannot override findings/authority |
| `GET /api/v1/tasks/{id}/events?version=1&limit=150&before=123` | Evidence page before a sequence, ascending; maximum requested page is 500 |

Omitting `version` preserves the existing current task/result behavior and
all-version notes/events reads. Legacy unversioned notes belong to version 1.
The dashboard requests a specific revision on every detail read. It initially
loads 150 records and allows bounded earlier-page inspection; full ledger storage
is unchanged. Selecting a finding filters loaded records by evidence reference.

Use the existing [Linux start instructions](linux_supervisor_round.md#reproduce-and-operate)
and [application configuration](runbook_application.md). Run exactly one control
plane on port 8000. Secrets and the evidence database stay outside every capsule.
Keep the integrity key stable for an existing database. To inspect an earlier
run, choose its revision in the dashboard. New revisions require verified prior
containment and fresh capsule/channel identities.

## Validation

The pulled checkpoint passed 176 Windows tests, 15 Linux-specific skips and 13
subtests. After these changes: **195 passed, 15 skipped, 13 subtests passed**.
The targeted owner/lifecycle tests, lint, formatting, application types (22 source
files), shared-schema compatibility and dashboard build passed. New regression
coverage includes revision races, historical signature corruption, paging,
owner-role separation, unknown source loss, quota isolation, nonblocking polling,
observer drain and cleanup error handling.

Synthetic browser verification checked current/historical revision selection,
disabled historical execution controls and saved plain-text review notes. It
used a private temporary database without sensor records, runtime bindings or
model calls. Missing coverage/binding remained visible. Existing committed Linux
artifacts were reviewed and left unchanged; no new live Linux run is claimed.
See [the machine-readable validation](application_completion_validation.json)
for audit results and their limits. The existing Starlette TestClient/httpx
deprecation warning remains.

## Member 2: complete the Linux acceptance round

Owner: @Gauravch-dev. Pull this application checkpoint and own all remaining
Linux/kernel/container/socket/sensor/model-host work. Preserve the shared schemas,
authorization, coverage/conflict gates, synthetic-only input and local-only model.

1. Rerun the combined tests and genuine continuous delivery/recovery pipeline.
   Exercise the new posture/revision APIs against actual supervisor state; verify
   source metrics, late historical delivery, final drain and shutdown behavior.
2. Establish monitoring from bootstrap birth. Do not backdate attachment or turn
   an initial observation gap into complete coverage.
3. Resolve partial file/network hook scope with an explicit supported-operation
   matrix, including inherited descriptors, mmap, io_uring and descendant/curl
   cases. Record unsupported mechanisms honestly.
4. Implement and verify trustworthy packet/process/cgroup attribution. Namespace
   packet capture alone cannot establish the originating process or content.
5. Resolve genuine source clock semantics and measured loss/export-failure
   accounting. Missing metrics remain unknown and cannot authorize complete
   coverage. Revalidate source restart/epoch/gap and durable replay behavior.
6. Only once the mandatory gates pass, run real admitted benign/injected Finance
   tasks through all three brokers. Return report receipts, correct totals,
   actual model identity/metrics, independent monitoring and verified descendant
   exit. Record a model's refusal as a refusal; deterministic attacks are separate.
7. Finish each S01–S16 case and measured application-log-only/network-only baseline
   comparison. Include cancellation, expiry, outage, restart and cross-capsule
   cases. Link sanitized source evidence and explicit blocked/unverified cases.
8. Commit and push the Linux implementation and reproducible results to this
   repository, then reply to issue #1 with the exact commit/branch, tests, artifact
   links and remaining blockers. No force push or gate relaxation.

Member 1's remaining joint work is to pull that return, reconcile the actual
admitted run/report and S01–S16 evidence, fix any demonstrated application issues,
and sign off application acceptance. A percentage cannot turn those missing
results into completion. Production SSO, multi-worker storage and public hosting
are outside this local MVP and are not prerequisites invented for this handoff.
