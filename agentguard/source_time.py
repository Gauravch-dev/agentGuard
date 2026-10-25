"""Exact source timestamp comparisons, before datetime's microsecond truncation.

Tetragon v1.7.0 converts each monotonic timestamp to wall time separately.
This module detects contradictions; it never adjusts source times or certifies
that conversion as an independently synchronized clock.
"""

import re
from datetime import UTC, datetime

PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})")


def nanoseconds(value):
    if not isinstance(value, str) or (match := PATTERN.fullmatch(value)) is None:
        raise ValueError("Bounded RFC3339 source timestamp required")
    whole = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
    delta = whole.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(
        (match[2] or "0").ljust(9, "0")
    )


def ordered_times(workload_start, process_start, observed, workload_end=None):
    start, process, event = map(nanoseconds, (workload_start, process_start, observed))
    return start <= process <= event and (
        workload_end is None or event <= nanoseconds(workload_end)
    )
