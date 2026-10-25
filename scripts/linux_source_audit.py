"""Bounded review of official pinned source and actual sensor metric exposure.

This is a diagnostic, not a source/binary equivalence proof or coverage approval.
No sensor timestamp, missing counter, or runtime admission flag is repaired.
"""

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

from agentguard.platform import command
from agentguard.schema import timestamp
from agentguard.supervisor import sensor_metrics

SOURCES = {
    "pkg/ktime/ktime.go": "34f69d5d894e0ee9a659502afb144553b6794bf9ba7ca4fa549ad52fe268bf08",
    "pkg/ktime/ktime_linux.go": "2303ebc720d63ded3cac296e1405c50668388ab73d96106704c524d09ac2eb50",
    "pkg/exporter/metrics.go": "9fa4600ca9102c9bd4f54d7e30c60f5d8ea449a8e94bca6028c4dbbcce813ec0",
    "pkg/exporter/exporter.go": "f46524e2f51c3acfba13b759fc1bf6ce642e1659704958fd4524dac4ea3e2f9c",
    "bpf/process/bpf_execve_event.c": "29bd471732b457186f926303edf8db3a4daf4cd4eb8787f06de97d89fbd6efe6",
    "pkg/process/process.go": "528a2ac50aa035080a9eb6b1280e0a9605ba6c9d7ffac9c41e7293496e5da4d0",
}


def run(output):
    sources = []
    bodies = {}
    for path, expected in SOURCES.items():
        url = "https://raw.githubusercontent.com/cilium/tetragon/v1.7.0/" + path
        with urllib.request.urlopen(url, timeout=15) as response:  # noqa: S310 - fixed HTTPS official source
            content = response.read(262145)
        if len(content) > 262144 or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("Pinned official source did not match its reviewed digest")
        bodies[path] = content.decode()
        sources.append({"url": url, "sha256": expected})
    info = json.loads(command(["docker", "inspect", "agentguard-tetragon"]))[0]
    metrics = sensor_metrics()
    report = {
        "observed_at": timestamp(),
        "mode": "pinned-source-and-live-metric-review",
        "sources": sources,
        "sensor_image": info["Config"]["Image"],
        "sensor_epoch": info["State"]["StartedAt"],
        "source_review": {
            "per_value_clock_conversion": "time.Now().Add(time.Duration(diff))"
            in bodies["pkg/ktime/ktime_linux.go"],
            "reviewed_kernel_exec_header_uses_same_time_as_process": "event->common.ktime = p->ktime;"
            in bodies["bpf/process/bpf_execve_event.c"],
            "process_wall_start_uses_separate_conversion": "ktime.ToProtoOpt(process.Ktime,"
            in bodies["pkg/process/process.go"],
            "documented_export_failed_family_declared_in_pinned_exporter": "events_export_failed_total"
            in bodies["pkg/exporter/metrics.go"],
            "live_exporter_enabled": any("export-filename" in arg for arg in info["Args"]),
        },
        "live_metric_series": metrics,
        "unavailable_families": [key for key, value in metrics.items() if value is None],
        "clock_decision": "Per-value monotonic/wall conversion explains a plausible source of the retained reversal; it does not establish an error bound or repair source ordering",
        "loss_decision": "File-exporter counters are separate from this gRPC subscriber. Source loss/merge/cache errors and collector queue failures still require measured accounting; absent values stay unknown",
        "limits": [
            "Matching source bytes is not proof of equivalence to the running image",
            "No default zero for absent counters, and no timestamp tolerance introduced",
            "This report is not a complete-coverage attestation",
        ],
        "protected_execution_ready": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=Path("docs/linux/source_semantics_review.json")
    )
    args = parser.parse_args()
    report = run(args.output)
    print(
        json.dumps(
            {
                "sources_verified": len(report["sources"]),
                "unavailable_families": report["unavailable_families"],
                "protected_execution_ready": False,
            }
        )
    )


if __name__ == "__main__":
    main()
