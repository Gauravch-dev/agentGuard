"""Evidence explanations, not a replacement for runtime/broker enforcement."""

from __future__ import annotations

from .schema import parse_time


def reconcile(contract, events, *, outcome="unknown", mode="unknown", integrity_ok=True):
    findings = []

    def add(label, reason, observation=None):
        findings.append({
            "classification": label, "reason": reason,
            "event_id": observation["event_id"] if observation else None,
            "evidence_reference": observation["evidence_reference"] if observation else None,
            "source": observation["source"] if observation else None,
        })

    if not integrity_ok:
        add("Unverified", "Evidence integrity verification failed; observations cannot establish safety.")
        return {"business_outcome": outcome, "execution_mode": mode, "classifications": ["Unverified"], "findings": findings}

    # Only a collector-generated, task-scoped interval attestation can establish coverage.
    # A process event, an empty log, or a broker's complete decision record cannot.
    host_covered = False
    for e in events:
        if (e["task_id"] != contract["task_id"] or e["contract_version"] != contract["contract_version"]):
            add("Unverified", "Event does not match this immutable contract version.", e)
            continue
        if e["source"] == "sensor_health":
            d = e["details"]
            if e["coverage_status"] in {"unavailable", "partial", "unknown"} or d.get("lost_events", 0) or d.get("export_failures", 0):
                add("Unverified", "Independent monitoring is incomplete for the stated interval or event classes.", e)
            # No live interval attestation is implemented in this initial release.
            continue
        if e["policy_verdict"] == "denied" and e["effect_status"] == "blocked" and e["source"] in {"trusted_broker", "policy_engine", "runtime"}:
            add("Blocked", "Trusted enforcement denied this operation; no completed leak is established.", e)
            continue
        if e["source"] == "runtime" and e["event_type"] == "runtime_lifecycle":
            if e["effect_status"] == "unknown":
                add("Unverified", "Runtime lifecycle could not be confirmed.", e)
            continue
        if e["coverage_status"] in {"unavailable", "unknown"} or e["effect_status"] in {"unknown", "attempted"}:
            add("Unverified", "Insufficient evidence to confirm this operation's effect.", e)
            continue
        if parse_time(e["observed_at"]) >= parse_time(contract["expires_at"]):
            add("Unexplained", "An observed effect occurred after contract expiry.", e)
            continue
        if e["source"] == "trusted_broker":
            if (e["operation"] in contract["allowed_operations"] and e["policy_verdict"] == "allowed"
                    and e["effect_status"] == "completed"
                    and (e["operation"] != "output.save_department_summary" or e["resource_or_destination"] == contract["approved_output_destination"])):
                add("Aligned", "Authenticated broker completed an authorized operation; assurance is scoped to its receipt.", e)
            else:
                add("Unexplained", "Broker effect has no matching authorized operation/destination.", e)
        elif e["source"] in {"host_sensor", "network_sensor"}:
            identity = e["process_identity"]
            if not identity.get("cgroup_id") or not identity.get("start_time"):
                add("Unverified", "Independent observation lacks stable process/cgroup attribution.", e)
            else:
                # Correlation IDs alone are not authorization; the live matcher is pending.
                add("Unexplained", "Attributable independent effect has no verified authorization match in the current matcher.", e)
        else:
            add("Unverified", "No supported authorization/effect rule explains this observation.", e)
    if not host_covered:
        add("Unverified", "No verified end-to-end independent host coverage interval is available. Broker alignment does not certify the whole task.")
    order = ["Blocked", "Unexplained", "Unverified", "Aligned"]
    return {
        "business_outcome": outcome, "execution_mode": mode,
        "classifications": [label for label in order if any(f["classification"] == label for f in findings)],
        "findings": findings,
    }
