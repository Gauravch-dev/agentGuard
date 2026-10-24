# Tetragon host integration — pending live validation

The sensor belongs outside the untrusted capsule. No sensor has been installed or launched in this build session.

The official [container deployment guide](https://tetragon.io/docs/installation/container/) currently illustrates release `v1.7.0`. Treat it as a version candidate, not a verified installation. A Linux owner must review the release, select and record an immutable image digest and confirm BTF/probe support on the actual kernel. Never put sensor privileges or host PID/cgroup access inside the agent image.

`agentguard.sensors.TetragonNormalizer` supports `process_exec` and `process_exit` JSON shapes with source time, process start time, container/docker identity and a trusted launcher lifecycle map. It retains unknown PIDs/binaries as null and does not log arbitrary command arguments. Mapping failures must become collector coverage gaps; they must not be filled with agent-provided identity. Stable source-record hashes support replay deduplication.

The adapter has fixture tests only. It does not authenticate a raw JSON file, run an exporter or declare collection healthy. The collector must preserve raw bytes/offset/hash outside capsule mounts, authenticate its transport, record receipt time, register unique sensor IDs, and maintain workload lifecycle bindings. Do not expose normalization as an agent-facing API.

Before protected execution, implement and test actual health/metrics polling and interval accounting. Candidate metrics in the [official reference](https://tetragon.io/docs/reference/metrics/) include `tetragon_bpf_missed_events_total`, `tetragon_observer_ringbuf_events_lost_total`, `tetragon_events_export_failed_total` and `tetragon_events_missing_process_info_total`; availability varies by release/configuration. Counter absence/reset, failed export, stalled stream and attribution gaps must become Unknown/Unverified rather than assumed zero loss.

File/open and connection tracing policies are deliberately not invented here. Capture supported hook behavior first: attempts versus successful operations, kernel argument schema, dropped events and whether pre-packet denials are visible. Commit narrow policies and captured sanitized fixtures only after that validation.

Reference: [Tetragon process and event API](https://tetragon.io/docs/reference/grpc-api/).
