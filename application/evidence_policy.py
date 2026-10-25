"""Application-only evidence conflict policy; shared wire schemas are unchanged."""

from application.models import Binding
from application.store import Store


def source_conflicts(store: Store, task_id: str, version: int) -> list[dict]:
    # Unversioned conflicts from the original application belong to revision 1.
    return [
        row
        for row in store.evidence(task_id, "ingestion_conflict")
        if row["body"].get("contract_version", 1) == version
    ]


def binding_has_conflicts(store: Store, binding: Binding) -> bool:
    return bool(source_conflicts(store, binding.task_id, binding.contract_version))
