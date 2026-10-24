# Architecture and trust boundaries

Owner -> reviewed Task Authority -> immutable contract -> trusted Member 2 adapter
-> untrusted capsule -> per-capsule Unix broker -> trusted aggregate/model/output
services. Registered host/network/policy collectors -> authenticated ingestion ->
append-only evidence -> pure TERE -> API -> React dashboard.

The application is trusted; prompts, model output and capsule requests are not.
Brokers resolve authority from a peer-verified binding, not task IDs in JSON. Output
storage and evidence are outside the capsule. Separate owner, runtime and per-source
sensor secrets enforce API boundaries. Missing/inconsistent data remain Unverified.
An attributable unapproved effect is Unexplained; an encrypted flow says nothing
about contents. Aligned findings are limited to supported operation evidence and
coexist with coverage gaps. No execution-wide safety score is calculated.

See original handoffs for Member 2's kernel/container/sensor ownership. The current
application cannot establish OS enforcement by itself. No platform/sensor code is
generated in their directories.
