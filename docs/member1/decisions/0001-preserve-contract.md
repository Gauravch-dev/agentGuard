# Decisions 0001 — preserve v1 and fail closed

- Preserve the original shared event fields/enums and task contract fields. Typed
  models generate JSON Schemas. A test checks both handoff examples unchanged.
- Additional schemas define transport/binding/coverage envelopes, not extensions to
  frozen v1 event semantics. Member 2 review remains pending; these are proposals.
- SQLite single-worker evidence ledger is the local prototype persistence choice;
  production PostgreSQL, roles, checkpoints and OS ACL deployment are pending.
- Local-only optional model provider; external transfer is disabled. Actual model
  calls are never replaced by a deterministic driver in live application code.
- Runtime unavailable means launch refused. Tests may inject adapter/model doubles;
  test-generated observations never count as live Linux proof.
- Exact report fields, three known departments, INR, decimal totals and no prose
  reduce content leakage. Model math and caller-specified destinations are rejected.
- Findings are plural; business completion never clears a blocked/unknown finding.
