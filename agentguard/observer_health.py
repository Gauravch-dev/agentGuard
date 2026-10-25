"""Conservative live observer assessment; no EOF/snapshot-to-complete promotion."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceHealth:
    alive: bool
    last_heartbeat: float | None
    pending: int = 0
    gaps: int = 0
    lost: int | None = None
    export_failures: int = 0
    epoch_changed: bool = False


def health_reasons(sources: dict[str, SourceHealth], checked: float) -> list[str]:
    reasons = []
    for name in ("process", "hooks", "packet"):
        source = sources.get(name)
        prefix = name.upper()
        if source is None or not source.alive:
            reasons.append(prefix + "_SOURCE_UNAVAILABLE")
            continue
        if source.last_heartbeat is None or not 0 <= checked - source.last_heartbeat <= 5:
            reasons.append(prefix + "_HEALTH_STALE")
        if source.pending:
            reasons.append(prefix + "_EXPORT_PENDING")
        if source.gaps:
            reasons.append(prefix + "_SOURCE_GAPS")
        if source.lost is None:
            reasons.append(prefix + "_LOSS_ACCOUNTING_UNKNOWN")
        elif source.lost:
            reasons.append(prefix + "_EVENT_LOSS")
        if source.epoch_changed:
            reasons.append(prefix + "_SOURCE_EPOCH_CHANGED")
    return reasons


def metric_delta(previous: dict, current: dict) -> tuple[int | None, bool]:
    """Missing, changed metric labels and resets are unknown loss, never zero."""
    if not previous or set(previous) != set(current):
        return None, True
    reset = False
    total = 0
    unknown = False
    for key, before in previous.items():
        after = current[key]
        if type(before) is not int or type(after) is not int or before < 0 or after < 0:
            unknown = True
        elif after < before:
            reset = True
        else:
            total += after - before
    return (None if unknown or reset else total), reset


def clock_compatible(previous_wall: float, previous_mono: float, wall: float, mono: float) -> bool:
    # This only detects host wall/monotonic discontinuity. It never attests the
    # separate kernel source timestamp semantics by itself.
    return mono >= previous_mono and abs((wall - previous_wall) - (mono - previous_mono)) <= 0.1
