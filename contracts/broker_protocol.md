# Broker protocol 1.0 (application proposal for Member 2 review)

The contract/event v1.0 wire fields and enums are unchanged from both original handoffs.
New transport envelopes do not extend `security_event.schema.json`.

Transport: one newline-delimited UTF-8 JSON request per connection on a private
per-capsule Unix socket; maximum frame 16 KiB; 5 second read timeout. Response maximum
32 KiB. No capsule-facing HTTP broker. Request schema: `broker_request.schema.json`.

```json
{"schema_version":"1.0","request_id":"client-retry-1","operation":"data.get_department_totals","payload":{}}
```

The agent's request ID is ONLY an idempotency hint, scoped to the channel's capsule.
The broker issues receipt IDs, evidence references and correlation IDs. Reusing an
ID with different content is rejected. Exact replay returns the persisted response.
No task ID, credential, SQL, path, destination or URL is accepted as authority.

Operations:
- `data.get_department_totals`: empty payload; returns exact synthetic aggregates.
- `model.generate_report_draft`: `{template_id:"finance_summary_v1",aggregates:<report>,document_id:"benign"|"injected"}`.
  Totals are independently verified. A fixed reviewed local model chooses the next tool
  action. Model output is untrusted. Disabled/unavailable models return unknown effect;
  no scripted fallback. Only controlled lab documents can be selected.
- `output.save_department_summary`: exact `{departments:[{department,total}],currency:"INR"}`.
  Exactly the three known departments, unique names and verified decimal totals;
  no commentary/extra keys. Internal destination is selected server-side.

Envelope: `{schema_version,receipt,result}`. Receipt schema captures task/capsule,
operation, verdict, effect status, classification, reason, trusted correlation ID,
evidence reference and timestamp. Denied attempts have no result. Full prompts,
credentials and rejected raw payloads are not stored. Request fingerprints use HMAC.

## Required peer resolution

`application.broker_transport.serve_socket` reads Linux `SO_PEERCRED` and calls a
trusted Member 2 `resolve_peer(pid,uid,gid)` callback. It must check `/proc` process
start identity and capsule cgroup against the registered launcher mapping, including
user namespaces and subprocesses. UID alone is insufficient. The callback returns
`ChannelContext(channel_id,capsule_id)`, never values from agent JSON. Test actual
socket mount permissions and cross-capsule restrictions before enabling live use.
The socket implementation is present but has not been tested on Linux here.

The trusted binding comes only from the runtime adapter's launch result, verified
by the application, never from a capsule or a public binding-registration endpoint.
Each new version requires a fresh capsule AND channel ID. Finished task channels
are refused. Per capsule: 32 broker actions, 4 model attempts, one report release,
16 KiB request, 30 second model timeout, 1024 output tokens; contract runtime and
expiry are rechecked on each action. This prototype runs one application worker.

## Runtime handoff

Implement `RuntimeAdapter.launch(contract_ref)`, `inspect(capsule_id)`,
`terminate(capsule_id)`, `observe()`. `contract_ref` is the immutable, verified typed
contract supplied in-process over a trusted adapter; no Docker arguments or paths.
`RuntimeResult` includes `readiness_passed`, effective `controls`, state, reason,
and trusted `Binding`. Required controls are exported in `runtime_adapter.py`.
No mock adapter ships in application code. The default adapter refuses launch.

Sensor ingestion uses distinct per-sensor Bearer credentials over a trusted local
channel, an operator-owned sensor registry, and host/source allowlists. Only a
registered `policy_engine` may assert allowed/denied policy verdicts; host/network
collectors use unknown/not_applicable. Exporter must route actual enforcement
observations through a registered policy decision identity. Original observation
time is unchanged; the application appends received time and sensor identity.
Simulation metadata stays outside the frozen event. Coverage has explicit class
scope, interval, lost-event count and source identity. Late observations are kept;
TERE marks window/clock inconsistencies rather than rewriting timestamps.

Concrete additional routes (application proposal, review together):
`POST /internal/v1/events`, `POST /internal/v1/coverage`,
`POST /internal/v1/tasks/{id}/completion`, `POST /api/v1/tasks/{id}/terminate`,
`POST /api/v1/tasks/{id}/revisions`, `POST /api/v1/tasks/{id}/notes`.
The six suggested shared task/health routes are preserved.
