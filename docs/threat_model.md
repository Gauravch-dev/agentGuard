# Threat model and current limits

## Assets and trusted components

Protect approved contracts, raw synthetic source rows, model credentials (none configured), released reports, workload identity and authoritative evidence. The host kernel, Docker daemon, Task Authority, broker code and collector administrators are trusted. A malicious host administrator, compromised kernel or compromised trusted broker is outside this prototype's protection boundary.

The AI agent, its subprocesses, prompt documents, arguments, claimed task identifiers, requested destinations and self-reported observations are untrusted. No arbitrary agent code runs in the Windows harness.

## Controls and gaps

| Threat | Implemented control | Remaining work |
|---|---|---|
| Agent self-grants access | Local authenticated owner approves a strict signed contract; broker context is bound outside request JSON | Enterprise identity and roles |
| Agent requests raw payroll or SQL | Only a parameter-free aggregate endpoint exists | Real database adapters with purpose-specific views |
| Raw rows through approved destination | Exact structured schema, recomputed totals, server-reconstructed release | Advanced lineage; arbitrary text release deliberately unsupported |
| Request spoofing/cross-task access | Caller task fields rejected; UDS peer UID/cgroup/start checks implemented | Real two-capsule socket/mount acceptance tests |
| Direct/child network escape | Fixed Docker network-none profile and Python/child active probes authored | Linux execution, DNS/UDP/curl adversarial tests |
| Excess runtime/resources | Memory/swap/PID/CPU/tmpfs/log/FD limits, host polling deadline | Crash-resilient watchdog; full protected lifecycle |
| Capsule forges OS evidence | No HTTP sensor ingestion endpoint; collector adapter stays host-side | Authenticated live transport and protected raw storage |
| PID reuse misattributes evidence | Trusted lifecycle interval, container prefix uniqueness, sensor process start | cgroup reuse, delayed delivery and process-exit live tests |
| Agent edits evidence | No state mount; append-only SQL triggers plus HMAC chain | External chain-head anchors, retention, encryption at rest |
| Sensor offline/loss/blind spots | Protected execution refused; Unverified always retained; output release coverage hook | Live health/metrics, interval attestation, automatic output hold tests |
| Local browser attack | Random bearer key, exact Host/Origin, no CORS, CSP, no unsafe HTML rendering | Production server hardening, HTTPS, RBAC, rate limits |
| Terminate button lies | Adapter requires captured cgroup, stopped runtime and `populated=0`/removed cgroup | Linux descendant termination tests; socket/lifecycle integration |

Local files use POSIX restrictive modes where supported. On Windows, `chmod` does not establish Unix-style access control. Windows profile ACLs are inherited and are **not audited** by this code. Do not share `.agentguard/` or run this control plane under an untrusted account.

An HMAC chain cannot prove completeness of a journal's tail without an independently stored head. It cannot resist an attacker who controls the signing key. The source of a normalized event is only trustworthy after its collector transport, credentials, raw files and lifecycle map have been authenticated; JSON shape alone provides no authenticity.

The current TERE cannot infer a process's business purpose from an executable name or a caller-supplied correlation ID. Unmatched independent process events stay Unexplained pending a reviewed matcher. A network flow never establishes its encrypted contents.

The Linux lab uses only a documentation-safe destination (`192.0.2.1`) and no payroll data or outbound payload. Timeout alone is not accepted as proof of network denial. No third-party network analyzer code has been reused.
