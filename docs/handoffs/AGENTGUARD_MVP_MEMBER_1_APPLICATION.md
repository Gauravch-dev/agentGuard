# AgentGuard 2.0 — MVP Member 1: Application, Agent & Security Intelligence Technical Handoff

**Audience:** You — developer of the hardware-light application and integration layer  
**Status:** Implementation handoff; **not implemented or validated yet**  
**Scope:** Full agreed **Minimum Viable Prototype (MVP)**, not a rushed simulation  
**Schedule:** No time constraints or delivery estimates in this plan  
**Project basis:** Final AgentGuard 2.0 TaskCapsule + Task-Effect Reconciliation architecture  
**Companion guide:** `AGENTGUARD_MVP_MEMBER_2_LINUX_PLATFORM.md`

> **Mission in one line:** Run a real AI task in a controlled, task-specific Linux environment, prevent unauthorized effects, and independently compare the task permissions with what the host and trusted services observed. Never claim a blocked attempt is a completed leak or that missing logs prove safety.

## 1. Your mission and responsibilities

You are **Member 1**, owner of the application/control plane that makes the project understandable and functional. Your part can be developed on a normal Windows laptop or MacBook; use Python, a local database and mocked runtime events *only for unit tests* while the real Linux sensor integration is under development.

**You own:** task authorization; versioned contracts; the real Finance Agent workflow; synthetic payroll data; data, model and output brokers; broker-side authorization; secure application APIs; protected evidence storage; Task-Effect Reconciliation Engine (TERE); simple incident dashboard; app and contract tests; final product integration.

**You do not own:** Linux kernel policy, Docker host isolation, host-level process sensors, network-flow capture, privileged Tetragon deployment or GPU setup. Those belong to Member 2. Do not present your simulated unit test events as live host evidence.

### End-to-end picture

```mermaid
flowchart TB
    USER[Authorized user] --> AUTH[Your Task Authority]
    AUTH --> CONTRACT[(Approved task contract)]
    CONTRACT --> ADAPTER[Shared runtime adapter]
    ADAPTER --> CAPSULE[Member 2 isolated TaskCapsule]
    CAPSULE --> BROKER[Your trusted local broker]
    BROKER --> DATA[Approved synthetic data]
    BROKER --> MODEL[Approved AI model]
    BROKER --> OUTPUT[Verified internal report]
    CONTRACT --> TERE[Your Task-Effect Reconciliation Engine]
    EVENTS[Member 2 host/network evidence] --> TERE
    BROKER --> TERE
    TERE --> DB[(Protected application/evidence store)]
    DB --> UI[Your investigation dashboard]
```

The TaskCapsule is **untrusted**; your broker and authority are **trusted**, run outside it, and must not obey privileges invented by its requests. Your task authority produces policies; Member 2 proves enforcement is loaded and effective.

## 2. MVP deliverables — all in scope

### A1. Task Authority and validated contracts

**Build:**
- An authenticated endpoint to create an approved task from a **pre-reviewed Finance task template**. An LLM may describe the objective but cannot invent new permissions.
- Persistent task record with approver, role, task purpose, permitted data operations, broker operations, output type/destination, expiry, policy version, limits and creation history.
- Signature or server-side integrity binding of approved contract references; reject tampering or expired contracts.
- Task lifecycle: `created -> approved -> launch_requested -> running -> completed|failed|interrupted`, separately from security findings.
- Revision path: no edits to an active contract that silently expand access; a new version needs trusted approval.

**Acceptance:** Invalid/expired contract or unexpected operation cannot reach launch; changing a file in the capsule does not modify the approved policy.

**Implementation suggestion:** FastAPI + Pydantic v2 models + PostgreSQL; JSON Schema generated from typed contract model; IDs created on trusted host, not by the AI agent. Authentication can start with a synthetic test-owner account, but never accept unrestricted self-approved privilege expansion.

### A2. Real AI Finance Agent and synthetic-company fixture

**Build:**
- Synthetic payroll fixture containing individual employee rows **only in the trusted data boundary**.
- Task: read authorized department totals, draft a department-wise report, and save internally.
- A real tool-using model call (hosted model through your trusted Model Broker, or optional teammate-hosted local model). **No provider keys inside the capsule**.
- One reproducible malicious-input demonstration (e.g. injected text in a synthetic document) and one benign version of the same workflow.
- Demo scenarios must use controlled laboratory inputs; no uploads to real unapproved external services.

**Important:** The agent runtime can be ordinary Python, LangGraph or a minimal tool-execution loop, but the first demonstration must involve an **actual model-driven tool choice**, not only scripted business logic. A deterministic agent/test driver can supplement it for repeatable security regression tests.

**Acceptance:** The real agent completes the legitimate report; an unsafe instruction may cause an attempted forbidden action, but neither the model prompt nor the document can change the trusted contract. If the model chooses not to perform an attack, use the deterministic adversarial driver for the enforcement demonstration and accurately label it.

### A3. Trusted Data Broker

**Build:**
- Predefined operations such as `data.get_department_totals`; no arbitrary SQL, file paths or agent-selected data source.
- Server-side lookup of contract by authenticated channel identity; per-task authorization and response limit.
- Return aggregated data, not row-level confidential data, for the salary-summary task.
- Generate broker receipt with request/correlation IDs, `allowed|denied`, resource classification, effect status and evidence reference.

**Acceptance:** Raw payroll table cannot be fetched from the capsule; a request not permitted by the task contract is denied and logged, including when made by a subprocess.

### A4. Trusted Model Broker

**Build:**
- An allowlisted model/provider, permitted prompt template and payload classifier appropriate to synthetic data.
- Keys held **outside** TaskCapsule; bound provider/client configuration; model request and response limits; budgets.
- Avoid forwarding arbitrary agent-specified URLs or unrestricted instructions; prevent raw sensitive rows from being sent by the model broker when contract permits aggregates only.
- Produce trusted model-call receipt and correlate to task, but do **not** log full prompts or secrets by default.

**Acceptance:** Real agent can use the approved model through the trusted broker. Model credentials never appear in capsule filesystem, env vars or child processes. Invalid operations/oversized payloads fail closed.

### A5. Trusted Output Broker

**Build:**
- Accept one typed report schema: `department_summary_v1` with fields such as `departments:[{department,total}]`, `currency`, and optional summary commentary (if allowing commentary, define strict content handling).
- Independently verify numeric totals against trusted Data Broker aggregates, or use trusted aggregation as the source of report values. Do not trust the LLM's math.
- Reject row-level payroll data, extra unexpected fields, external recipients, oversized documents or mismatched totals.
- Save only to a known internal reports store (server-side destination); produce an immutable release receipt.

**Acceptance:** Normal report passes. Raw salaries inside extra fields, incorrect totals, forbidden destination or invalid format are denied. Distinguish denial from completed successful storage.

### A6. Application API and persistent storage

**Build:**
- Task management, run status, event viewer and report retrieval APIs from shared spec.
- Dedicated database tables for contracts/versions, capsule registrations, broker receipts, normalized events, coverage windows, findings, task results and human notes.
- Access control: user-facing API and privileged internal runtime ingestion should not share unrestricted credentials.
- Schema validation and rate limits; all ingested host events carry authenticated source identity. Never trust arbitrary events posted by a capsule.
- Audit log append-only at application level; storage/OS hardening coordinated with Member 2.

**Suggested tables:** `task_contracts`, `capsule_bindings`, `broker_receipts`, `security_events`, `sensor_coverage`, `security_findings`, `task_results`, `review_notes`.

### A7. TERE — deterministic, evidence-aware reconciliation

**Build this as a testable pure service first.** Inputs: authenticated task contract, capsule binding, broker receipts, host/network observations, sensor-health/coverage windows.

Algorithm:
1. Confirm task and contract version were approved; check capsule/cgroup mapping provenance.
2. Group events within task execution window, retaining source timestamps and receipt timestamps.
3. Correlate authenticated broker receipts, cgroup/container/process identity and other trustworthy links; mark uncertain joins.
4. Compare each observed action to the task's permitted resources, operations, output type and destination.
5. Emit a **list of findings**: `Aligned`, `Blocked`, `Unexplained`, `Unverified`, with reason codes, coverage notes, evidence references and confidence limitations.
6. Store **business outcome separately** from security findings and permit follow-up human review.

Examples of proposed reason codes: `DENIED_OPERATION`, `UNAPPROVED_DESTINATION`, `UNMATCHED_HOST_EFFECT`, `MISSING_SENSOR_COVERAGE`, `UNTRUSTED_EVENT_SOURCE`, `OUTPUT_SCHEMA_VIOLATION`, `INVALID_CONTRACT`.

**Never implement:** “No events => safe,” “blocked upload => actual leak,” “encrypted 5 MB flow => payroll exfiltration,” or “LLM says safe => override hard denial.”

**Acceptance:** Tests S01–S16 in shared contract, plus table-driven edge cases (duplicate events, clock skew, PID reuse, broker failure, sensor loss, rejected output, task finished while security incident ongoing).

### A8. Investigation dashboard

Make a **functional, simple React dashboard**, not a large security operations center mockup. Sections:
- Task: approved objective, effective permissions, approver, launch status, runtime identity.
- Evidence: time-ordered events with source labels (`host`, `broker`, `network`, `health`) and gaps.
- Findings: separate cards for `Aligned`, `Blocked`, `Unexplained`, `Unverified`, reason and linked evidence.
- Business result: approved report, failed step, or interruption.
- Security posture: whether the sandbox readiness gate passed, sensor health and last receipt.

**Acceptance:** The UI retrieves real backend data; a simulated fixture must be plainly marked test data. No “Isolated” or “Blocked” badge appears just because a button was clicked—wait for verified runtime/broker outcome.

## 3. Your implementation order (dependencies, NOT a schedule)

1. **Agree the shared schemas** with Member 2; add contract tests and typed fixture generators.
2. Define trusted task contracts and create synthetic fixtures.
3. Build broker operations in-process and test allow/deny before exposing them to a capsule.
4. Define the Unix-socket protocol/adapter; test against a benign dummy client before AI model integration.
5. Build pure TERE evaluation on clearly marked fixture events. Require coverage assessment.
6. Connect actual Member 2 launcher events and host sensor data; remove demo-only assumptions from live mode.
7. Connect the real Finance Agent to brokers; verify authorized report and policy denial cases.
8. Add dashboard and protected persistence.
9. Run complete security demonstration, baseline comparisons and measured results together.

## 4. Exact handoffs you must deliver to Member 2

| Artifact / interface | What you provide |
|---|---|
| `contracts/task_contract.schema.json` | Frozen contract schema and version |
| `contracts/security_event.schema.json` | Frozen event fields, enums and validation |
| `contracts/broker_protocol.md` | Versioned Unix-socket JSON protocol and request/response envelopes |
| `application/runtime_adapter.py` | Application-side interface expectations: launch, status, terminate, observe |
| `tests/contract/` | Fixtures and schema compatibility checks |
| `tests/e2e/` | Expected scenarios and outcomes; joint ownership |
| `docs/integration_status.md` | Which end-to-end properties are genuinely passing |

Before integration, Member 2 must provide a signed/registered mapping `task_id -> capsule_id -> host_id -> cgroup/process identity`. You must reject host evidence with invalid or missing trusted mappings rather than guessing attribution from PID or time proximity alone.

## 5. Application-side threats and mitigations

| Threat | Your implementation rule |
|---|---|
| Agent invents a different `task_id` | Resolve authority from trusted launch/socket binding |
| Prompt injection requests extra permissions | Treat prompt/document text as untrusted data |
| Raw payroll rows sent through approved service | Output Broker validates content, schema and task need |
| External model used as exfiltration route | Only Model Broker can call provider; enforce payload policy |
| SSRF / arbitrary URLs in broker requests | No arbitrary target URLs or user-defined SQL/paths |
| Multiple agent tasks share data | Separate task storage and authorized release of artifacts |
| Host event forged by capsule | Require authenticated sensor ingestion and provenance |
| Missing events | `Unverified`, never `Aligned` |
| LLM failure / quota exhaustion | Report model failure; no fabricated task completion |
| UI toggles status without actual enforcement | Query trusted runtime result, not client state |

## 6. Functional completion checklist — Member 1

- [ ] Approved task contract created, versioned and immutable to agent.
- [ ] Unapproved task operation refused by broker.
- [ ] Synthetic data available only through permitted data operation.
- [ ] Actual AI model used through approved Model Broker; no leaked API secrets.
- [ ] Output Broker validates numeric values, schema and internal destination.
- [ ] Task lifecycle and broker/host events stored with trust/provenance.
- [ ] TERE emits evidence-linked findings and recognizes missing coverage.
- [ ] Dashboard explains both task outcome and security outcomes.
- [ ] Automated unit, contract, and application integration tests pass.
- [ ] Joint S01–S16 tests pass or clearly identify explicit limitations.
- [ ] Results and failures recorded honestly; no performance or novelty claims without tests.


## Shared integration contract — identical requirements for both members

**Freeze these interfaces before implementing either half.** Changes need an agreed schema version, a compatibility test and a brief decision record. This specification is a *proposed MVP contract*, not a claim that any library produces these fields automatically.

### A. Identifiers, ownership and trust

| Field | Meaning | Issuer / authority |
|---|---|---|
| `task_id` | Unique approved business task, e.g. `FIN-001` | Member 1 Task Authority |
| `contract_version` | Immutable version of approved task permissions | Member 1 Task Authority |
| `capsule_id` | Unique isolation instance for one task execution | Member 2 trusted Launcher |
| `host_id` | Linux host or VM identifier | Member 2 host service |
| `cgroup_id` / process start identity | OS evidence-to-capsule mapping | Member 2 host sensor/launcher |
| `correlation_id` | Per broker action/release trace identifier | Trusted broker or launcher, never agent authority |
| `event_id` | Unique observation identifier for deduplication | Collector at ingestion |
| `sensor_id` | Registered source of host/network evidence | Member 2 sensor registry |

**Trust boundary:** The AI agent is untrusted. A `task_id`, `agent_id`, `destination`, policy verdict, or claimed result supplied by it is **not** an authorization credential or proof. The trusted launcher binds capsule identity to an approved contract. Broker authentication uses a launcher-provisioned, per-capsule communication channel and validates peer/access context; do not accept a caller-chosen task ID as sufficient proof. The exact OS-level peer validation mechanism must be tested and documented for the chosen container/user namespace configuration.

### B. Task contract schema — version 1

```json
{
  "schema_version": "1.0",
  "task_id": "FIN-001",
  "contract_version": 1,
  "approved_by": "authorized-finance-task-owner",
  "agent_role": "finance-reporting",
  "objective": "Prepare department-wise totals from synthetic payroll",
  "allowed_operations": [
    "data.get_department_totals",
    "model.generate_report_draft",
    "output.save_department_summary"
  ],
  "allowed_data_classes": ["synthetic_payroll_aggregate"],
  "approved_output_destination": "internal_reports",
  "output_schema": "department_summary_v1",
  "direct_internet_allowed": false,
  "expires_at": "2026-12-31T00:00:00Z",
  "limits": { "max_execution_seconds": 180, "max_memory_mb": 768, "max_processes": 64 }
}
```

The date and limits above are **illustrative test values**, not mandated production defaults. Contract signatures/hashes, expiration and approval must be verified server-side. The agent cannot modify an approved contract.

### C. Normalized security event schema — version 1

```json
{
  "schema_version": "1.0",
  "event_id": "7f6b7c2a-c8dd-4324-a4a7-121212121212",
  "task_id": "FIN-001",
  "contract_version": 1,
  "capsule_id": "capsule-001",
  "host_id": "linux-host-01",
  "source": "host_sensor",
  "event_type": "process_exec",
  "observed_at": "2026-10-23T12:00:00Z",
  "process_identity": {
    "pid": 4820,
    "start_time": "2026-10-23T11:59:59Z",
    "cgroup_id": "cg-illustrative"
  },
  "operation": "execute",
  "resource_or_destination": "python report.py",
  "policy_verdict": "not_applicable",
  "effect_status": "observed",
  "coverage_status": "complete",
  "correlation_id": null,
  "evidence_reference": "evidence-0001"
}
```

Required enums and semantics:

| Field | Allowed values | Rule |
|---|---|---|
| `source` | `host_sensor`, `network_sensor`, `trusted_broker`, `policy_engine`, `runtime`, `sensor_health` | Preserve genuine source; no synthetic events disguised as host evidence |
| `event_type` | `process_exec`, `process_exit`, `file_access`, `connection_attempt`, `egress_flow`, `broker_request`, `broker_release`, `policy_denial`, `sensor_health`, `runtime_lifecycle` | Extend only through versioned schema review |
| `policy_verdict` | `allowed`, `denied`, `not_applicable`, `unknown` | Only a trusted decision point can assert `allowed` or `denied` |
| `effect_status` | `attempted`, `blocked`, `observed`, `completed`, `unknown` | `observed` means an event seen, not necessarily a confirmed data leak |
| `coverage_status` | `complete`, `partial`, `unavailable`, `unknown` | `complete` is scoped to explicitly documented event classes and interval, not all activity |

Unknown fields from a sensor remain `null` or `unknown`; do **not fabricate** PID, destination, amount transferred or denial information to fill gaps. Deduplicate by stable source/event identity. Preserve event receipt time separately from source observation time. Synchronize host clock.

### D. Broker transport and approved operations

**Initial controlled transport:** capsule has Docker `--network none` (only loopback), while a trusted host process provides a **per-capsule Unix-domain socket** mounted at a restricted path. Socket exposure is a limited communication channel, not unrestricted network connectivity. Its directory/file permissions, container user-namespace effects, peer identity and cross-capsule access restrictions must be explicitly tested. No host Docker socket is ever mounted.

A simple **versioned JSON request/response** protocol suffices for MVP. One broker service may multiplex the three logical operations while preserving separate authorizers and credentials:

| Operation | Input | Trusted output / guarantee |
|---|---|---|
| `data.get_department_totals` | No raw SQL, no arbitrary file path | Approved synthetic department aggregates only; log source classification |
| `model.generate_report_draft` | Prompt *template identifier* + permitted aggregates | Approved hosted or optional local model response; provider credentials remain outside capsule |
| `output.save_department_summary` | Structured `{departments:[{department,total}], currency}` | Validate exact allowed keys, numeric totals/aggregation, approved internal destination; deny raw salary rows |

A broker validates the channel-bound task identity, contract version, requested operation, payload schema, maximum size and output classification. Agent-specified `task_id`, URLs, file paths or SQL are never trusted as authority. If a broker cannot verify its policy or trust context, it rejects the operation.

### E. System lifecycle and status API

The application exposes these logical API capabilities (concrete routes are suggested and can be adapted **together**):

```text
POST /api/v1/tasks                   -> validate/store approved task contract
GET  /api/v1/tasks/{task_id}         -> task + current status
POST /api/v1/tasks/{task_id}/launch  -> authenticated control-plane launch request
GET  /api/v1/tasks/{task_id}/events  -> normalized, source-attributed events
GET  /api/v1/tasks/{task_id}/result  -> business outcome + security assessment
GET  /api/v1/health                  -> application readiness
```

Member 2 provides a **trusted local runtime adapter** with `launch(contract_ref)`, `inspect(capsule_id)`, `terminate(capsule_id)` and an event stream; Member 1 owns the application routes. The runtime adapter must not accept arbitrary client-supplied Docker arguments or privileged host paths.

**Do not conflate:** business task outcome (`completed`/`failed`/`interrupted`) with security classification (`Aligned`/`Blocked`/`Unexplained`/`Unverified`). A single task can have a successful report and a blocked attack attempt. Multiple security findings may coexist for one task.

### F. Reconciliation classifications

| Classification | Meaning | Evidence condition |
|---|---|---|
| **Aligned** | Permitted operation with supporting evidence | Verified contract + authenticated broker/OS observation **within stated coverage** |
| **Blocked** | Prohibited operation denied before effect | Trusted enforcement denial, plus independent attempt evidence **if available**; note the limitation if it is missing |
| **Unexplained** | Security-relevant host/network effect lacks adequate authorized explanation | Attributable observed event without a matching approved operation |
| **Unverified** | Evidence insufficient or untrusted | Sensor gap, failed attribution, conflicting records or missing effect confirmation |

**Precedence:** A confirmed blocked attempt remains `Blocked` even if the business task succeeds; missing required evidence also creates a distinct `Unverified` coverage finding. Do not force an entire task into a single exclusive status; return a list of findings with evidence references and a separate summary view. A blocked connection is **not** proof that data left the machine. An encrypted flow is **not** proof of its contents.

### G. Shared acceptance scenarios

| ID | Test | Required evidence/outcome |
|---|---|---|
| S01 | Approved synthetic payroll summary | Valid report saved internally; task business success |
| S02 | Forbidden file read | Access denied by effective OS/file policy; log decision and any host observation |
| S03 | Direct HTTP/HTTPS egress, by Python | Denied under actual capsule restrictions; no successful flow |
| S04 | Equivalent attempt using `curl` or child process | Same restrictions apply to descendants |
| S05 | DNS/direct-IP/alternative-protocol bypass attempts in a controlled lab | No unauthorized route; accurately record what is and is not observable |
| S06 | Raw payroll rows passed to output broker | Broker rejects them, even for an approved destination |
| S07 | Approved model call via broker | Credential never reaches capsule; response processed appropriately |
| S08 | Invalid/expired task contract | Launch rejected; no capsule started |
| S09 | Security readiness failure | Launch refused and reason recorded; no silent fallback |
| S10 | Sensor stopped / dropped events | `Unverified` coverage finding, never silently `Aligned` |
| S11 | Unknown host/network effect attributed to capsule | `Unexplained` finding with raw evidence reference |
| S12 | Agent task completes after unauthorized operation blocked | Business success and blocked security event both visible |
| S13 | Cross-capsule socket or data access attempt | Unauthorized cross-task access denied |
| S14 | Capsule terminate request | Confirm process/cgroup exit and absence of live descendants; request alone is not proof |
| S15 | Restart task with fresh capsule | No inherited credentials, arbitrary prior memory or unexpected files |
| S16 | Baseline comparison | Report differences versus application-logging-only and network-only observations, without invented efficacy numbers |

**Evidence quality rule:** If a sensor cannot truly record a blocked attempt with the deployed hook/policy, label the observation unavailable and show broker/runtime denial separately. Do not create fake process or flow telemetry to make the dashboard look complete.

### H. Repository, integration and security rules

Recommended shared layout:

```text
agentguard/
  contracts/                 # JSON Schema/OpenAPI; reviewed jointly
  application/               # Member 1: APIs, authority, brokers, TERE
  agent_demo/                # Member 1: synthetic company and AI agent
  dashboard/                 # Member 1: React investigation UI
  platform/                  # Member 2: launcher, profiles, preflight
  sensors/                   # Member 2: host/network collectors and exporters
  tests/
    unit/                    # owner per module
    contract/                # both maintain
    security_lab/            # Member 2 leads; Member 1 checks results
    e2e/                     # jointly maintained
  docs/
    architecture.md
    threat_model.md
    decisions/
    experiment_results.md
    integration_status.md
  .env.example               # placeholders only; never real secrets
```

- Separate module ownership; no unreviewed changes to the other's directories, schema or trust model.
- Shared contract tests run for both repositories/branches before merging.
- Use synthetic data, owned test hosts and documentation-safe destinations; do not send confidential payroll data or attack unrelated services.
- Never commit API keys, passwords, live tokens or production customer data.
- Run formatter, type checker, automated tests, dependency and secret scanning; review privileged code and input-validation changes.
- Pin container image and tool versions; record Linux kernel capabilities. Optional local-model runtime cannot require exposing an unrestricted model-provider endpoint to capsule.
- When a test fails, report the actual failure and missing observation; no simulated "success" fallback.
- Deliver changes with an updated runbook, relevant tests and evidence references. Do not announce a security feature completed based on UI behavior alone.
- Explicitly differentiate third-party technology from our authored integration and algorithms.

## References — primary technical documentation

- AgentGuard finalized master guide: `AGENTGUARD_2_0_PROJECT_MASTER_GUIDE.md`.
- Python FastAPI: https://fastapi.tiangolo.com/ ; Pydantic: https://docs.pydantic.dev/latest/ .
- Docker none network driver: https://docs.docker.com/engine/network/drivers/none/ .
- Tetragon installation/FAQ: https://tetragon.io/docs/installation/faq/ .
- NIST Secure Software Development Framework: https://csrc.nist.gov/pubs/sp/800/218/final .
- OWASP Agentic Security: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ .
- TeamSynapse legacy network project (evaluate security before reuse): https://github.com/Hack-On-Tracks/TeamSynapse .

**Handoff success condition:** An ordinary model-driven Finance Agent produces the approved aggregate report, unauthorized output and network/file attempts are blocked by external controls, and the dashboard shows independent evidence and honest uncertainty—not a merely simulated security verdict.
