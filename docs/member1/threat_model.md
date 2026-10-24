# Threat model

In scope: prompt injection requesting extra permissions; forged task identifiers;
raw-row payloads; wrong aggregates; model/provider URL injection; output destination
injection; broker replay; cross-task binding confusion; source spoofing; missing
observations; clock skew; PID reuse; lifecycle/incident confusion; runtime readiness
and termination false assurance; accidental credential persistence.

Controls: fixed reviewed Finance template; approval integrity; strict schema and
limits; exact numeric verification; fixed loopback model client; server-selected
internal output; task-bound peer channel; replay fingerprint and persistent receipt;
fresh capsule/channel uniqueness; source/host registry; separate credentials;
append-only HMAC evidence; explicit coverage windows; cgroup AND start identity;
plural findings; independent runtime inspection; no default live model or launch.

Limits: compromised trusted host/provider/collector; OS peer enforcement pending
Linux validation; no hardware attestation; no immutable remote log/checkpoint; no
production identity system; local owner credential is privileged; concurrent
multi-worker deployment unsupported; API rate limiting is process-local; model
safety/refusal is not an enforcement guarantee. Contract bound prevents access
expansion by the agent, not arbitrary privileged operator/host compromise.
