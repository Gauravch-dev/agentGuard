# Staging startup correction — 26 October 2026

The dashboard demonstration failed with `STAGING_FAILED` before any Finance agent
code was admitted. The private diagnostic identified a tracing-policy RPC deadline,
not a successful admission hold: the old 40-second request expired while the pinned
sensor was still installing the expanded 19 entry/return hook pairs. Sensor logs
then showed cancellation and invalid internal hook identifiers during cleanup.

The load RPC now has a bounded 90-second setup timeout and a 95-second host command
timeout. The sensor was restarted with no active tasks before verification. Every
hook, explicit root witness, identity check and admission gate remains required.
The capsule's original wall-clock and monotonic deadlines are unchanged and are
checked again before bootstrap startup. A regression test simulates setup consuming
the entire deadline and verifies that the bootstrap cannot start, the deadline is
not extended, and observer cleanup runs.

The dashboard now displays **Preparing restricted environment** during the request
and explains that monitoring setup can take up to two minutes. An approved task is
not shown as evidence that an agent has started.

## Verification

- A fresh real application/Docker/sensor run staged in **56.745 seconds** and passed
  all nine checks: genuine pre-start process/hook witnesses, registered bootstrap,
  no admitted agent, original execution limit, admission held on missing coverage,
  no report, verified evidence chain and verified cleanup.
- [Sanitized live result](linux/staging_startup_review.json).
- [Linux regression checks](linux/validation_linux.json): 232 tests and 13 subtests
  passed; lint, formatting, application types and contract compatibility passed.
- Dashboard TypeScript/Vite production build passed.
- Retrying the original failed task as a new approved revision in the visible
  dashboard reached **Waiting for admission** with a registered runtime identity.
  Its cancellation completed with no active tasks left. The original failed
  revision remains in the evidence history.

To repeat against the running configured Linux application:

```sh
/var/lib/agentguard/venv/bin/python -m scripts.linux_staging_smoke
```

The command creates its own synthetic task, checks the admission refusal and
cleans up its staged capsule. Its default report is `var/staging-smoke.json`.
This is a staging regression check; full protected Finance execution remains
held by the coverage, packet attribution and source clock/loss gaps documented in
[the delivery return](linux_delivery_round.md).
