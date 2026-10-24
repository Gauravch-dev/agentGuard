# Shared contract v1

`task-contract-v1.schema.json` and `security-event-v1.schema.json` describe the strict local implementation. `agentguard/schema.py` additionally enforces time-dependent expiry, request size, operation support and semantic constraints; a JSON Schema document alone is not authorization.

The Linux handoff's contract is used instead of the presentation guide's illustrative variant. Additional v1 event metadata is explicitly versioned here: `received_at` and `details` are required. `details` carries source-specific coverage scope and explanations. `process_identity` unknown members remain null. Event `coverage_status=complete` describes only the source's declared scope; a complete broker receipt is not complete host coverage.

Approval is local-owner-only in this prototype. A client-supplied `approved_by` must equal the authenticated server-side approver; its name does not prove authority by itself. HMAC signatures are verified on every contract load. Versions are immutable and monotonically increment by one for each task.

The broker wire envelope is exactly `{schema_version, operation, payload}`. Caller-supplied task IDs, destinations, raw SQL and arbitrary file paths are rejected. Context comes from trusted `Binding` and the Linux socket authorizer. The API has no generic event ingestion route.

Local API routes:

| Method | Route | Behavior |
|---|---|---|
| GET | `/api/v1/health` | App ready, protected execution false |
| GET | `/api/v1/snapshot` | Contracts, run list, integrity |
| POST | `/api/v1/tasks` | Local owner approves strict contract |
| GET | `/api/v1/tasks/{id}` | Latest contract |
| POST | `/api/v1/tasks/{id}/launch` | Refuses until live protected integration is validated |
| POST | `/api/v1/tasks/{id}/harness` | Trusted synthetic checks, `{}` only |
| GET | `/api/v1/tasks/{id}/events` | Source-attributed task journal |
| GET | `/api/v1/tasks/{id}/result` | Latest run, report and concurrent findings |
| GET | `/api/v1/runs/{harness-id}` | Specific harness result |

All API routes require the local bearer key and exact loopback Host. Browser requests must have the matching origin. These are local-development interfaces, not a production identity service.
