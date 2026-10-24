"""Shared wire v1; trust and receipt metadata live in separate envelopes."""

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
Source = Literal[
    "host_sensor", "network_sensor", "trusted_broker", "policy_engine", "runtime", "sensor_health"
]
EventType = Literal[
    "process_exec",
    "process_exit",
    "file_access",
    "connection_attempt",
    "egress_flow",
    "broker_request",
    "broker_release",
    "policy_denial",
    "sensor_health",
    "runtime_lifecycle",
]
State = Literal[
    "created", "approved", "launch_requested", "running", "completed", "failed", "interrupted"
]
OPERATIONS = (
    "data.get_department_totals",
    "model.generate_report_draft",
    "output.save_department_summary",
)


def now() -> datetime:
    return datetime.now(UTC)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class Limits(StrictModel):
    max_execution_seconds: int = Field(default=180, ge=1, le=180)
    max_memory_mb: int = Field(default=768, ge=64, le=768)
    max_processes: int = Field(default=64, ge=1, le=64)


class TaskContract(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    task_id: Identifier
    contract_version: int = Field(ge=1)
    approved_by: Identifier
    agent_role: Literal["finance-reporting"] = "finance-reporting"
    objective: Literal["Prepare department-wise totals from synthetic payroll"] = (
        "Prepare department-wise totals from synthetic payroll"
    )
    allowed_operations: tuple[str, ...] = OPERATIONS
    allowed_data_classes: tuple[Literal["synthetic_payroll_aggregate"], ...] = (
        "synthetic_payroll_aggregate",
    )
    approved_output_destination: Literal["internal_reports"] = "internal_reports"
    output_schema: Literal["department_summary_v1"] = "department_summary_v1"
    direct_internet_allowed: Literal[False] = False
    expires_at: AwareDatetime
    limits: Limits = Limits()

    @field_validator("allowed_operations")
    @classmethod
    def approved_operations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(set(value)) != len(value) or not set(value) <= set(OPERATIONS):
            raise ValueError("operations must be a unique subset of the reviewed template")
        return value


class EmptyRequest(StrictModel):
    pass


class CreateTask(StrictModel):
    template_id: Literal["finance_summary_v1"] = "finance_summary_v1"


class ProcessIdentity(StrictModel):
    pid: int | None = Field(default=None, ge=1)
    start_time: AwareDatetime | None = None
    cgroup_id: Identifier | None = None


class SecurityEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    event_id: Identifier
    task_id: Identifier
    contract_version: int = Field(ge=1)
    capsule_id: Identifier
    host_id: Identifier
    source: Source
    event_type: EventType
    observed_at: AwareDatetime
    process_identity: ProcessIdentity | None = None
    operation: str | None = Field(default=None, max_length=128)
    resource_or_destination: str | None = Field(default=None, max_length=1024)
    policy_verdict: Literal["allowed", "denied", "not_applicable", "unknown"] = "unknown"
    effect_status: Literal["attempted", "blocked", "observed", "completed", "unknown"] = "unknown"
    coverage_status: Literal["complete", "partial", "unavailable", "unknown"] = "unknown"
    correlation_id: Identifier | None = None
    evidence_reference: Identifier | None = None


class EventEnvelope(StrictModel):
    event: SecurityEvent
    sensor_id: Identifier
    received_at: AwareDatetime
    simulated: bool = False


class Binding(StrictModel):
    task_id: Identifier
    contract_version: int = Field(ge=1)
    capsule_id: Identifier
    host_id: Identifier
    cgroup_id: Identifier
    process_start: AwareDatetime
    registered_at: AwareDatetime
    channel_id: Identifier
    simulated: bool = False


class Coverage(StrictModel):
    coverage_id: Identifier
    task_id: Identifier
    capsule_id: Identifier
    sensor_id: Identifier
    source: Literal["host_sensor", "network_sensor"]
    event_classes: tuple[EventType, ...] = Field(min_length=1)
    start: AwareDatetime
    end: AwareDatetime
    status: Literal["complete", "partial", "unavailable", "unknown"]
    lost_events: int = Field(default=0, ge=0)
    simulated: bool = False

    @model_validator(mode="after")
    def interval(self) -> "Coverage":
        if self.end <= self.start:
            raise ValueError("coverage interval must be positive")
        return self


Money = Annotated[Decimal, Field(ge=0, le=1_000_000_000, max_digits=12, decimal_places=2)]


class Department(StrictModel):
    department: Literal["Engineering", "Finance", "Operations"]
    total: Money


class Report(StrictModel):
    departments: tuple[Department, ...] = Field(min_length=3, max_length=3)
    currency: Literal["INR"] = "INR"


class ModelRequest(StrictModel):
    template_id: Literal["finance_summary_v1"]
    aggregates: Report
    document_id: Literal["benign", "injected"] = "benign"


class BrokerRequest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    request_id: Identifier
    operation: Annotated[str, Field(min_length=1, max_length=128)]
    payload: dict = Field(default_factory=dict)


class ToolChoice(StrictModel):
    operation: Annotated[str, Field(min_length=1, max_length=128)]
    payload: dict = Field(default_factory=dict)


class Receipt(StrictModel):
    receipt_id: Identifier
    task_id: Identifier
    capsule_id: Identifier
    request_id: Identifier
    correlation_id: Identifier
    operation: str
    verdict: Literal["allowed", "denied"]
    effect_status: Literal["blocked", "completed", "unknown"]
    reason: str
    classification: Literal["synthetic_payroll_aggregate"] = "synthetic_payroll_aggregate"
    evidence_reference: Identifier
    observed_at: AwareDatetime


class BrokerResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    receipt: Receipt
    result: dict | None = None


class Finding(StrictModel):
    classification: Literal["Aligned", "Blocked", "Unexplained", "Unverified"]
    reason_code: str
    explanation: str
    evidence_references: tuple[str, ...] = ()


class RuntimeResult(StrictModel):
    state: State
    readiness_passed: bool
    controls: tuple[str, ...] = ()
    reason: str
    binding: Binding | None = None
    descendants_exited: bool = False
    simulated: bool = False


class Completion(StrictModel):
    state: Literal["completed", "failed", "interrupted"]
    capsule_id: Identifier
    descendants_exited: bool


class ReviewNote(StrictModel):
    text: Annotated[str, Field(min_length=1, max_length=2000)]
