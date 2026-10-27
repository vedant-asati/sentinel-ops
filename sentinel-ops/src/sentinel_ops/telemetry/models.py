"""Typed, immutable telemetry observations, probe attempts, and snapshot schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field


AttemptStatus = Literal[
    "SUCCESS",
    "EMPTY",
    "UNSUPPORTED",
    "INVALID_MEASUREMENT",
    "STALE_TELEMETRY",
    "TOOL_FAILURE",
    "BUDGET_EXCEEDED",
]

CoverageStatus = Literal["COMPLETE", "PARTIAL", "EMPTY", "UNKNOWN"]

JoinStatus = Literal[
    "single_series",
    "label_joined",
    "unjoinable",
    "missing_denominator",
]


class ProbeAttempt(BaseModel):
    """Audit record for a single backend telemetry read attempt."""

    model_config = ConfigDict(frozen=True)

    attempt_id: str
    probe_key: str
    backend: Literal["prometheus", "tempo"]
    service: str
    signal_name: str
    requested_window: Tuple[str, str]
    query_string: str
    attempt_number: int = 1
    status: AttemptStatus
    duration_ms: float = 0.0
    acquired_at: str = ""
    error_detail: Optional[str] = None
    total_series_count: Optional[int] = None
    retained_series_count: Optional[int] = None
    truncated: bool = False
    coverage_status: CoverageStatus = "UNKNOWN"


class NormalizedMetricObservation(BaseModel):
    """Typed metric measurement anchored to explicit entity labels and incident window."""

    model_config = ConfigDict(frozen=True)

    observation_id: str
    attempt_id: str
    attempt_ids: Tuple[str, ...] = ()
    sample_revision: str = ""
    backend_source: Literal["prometheus"] = "prometheus"
    service: str
    signal_name: str
    entity_labels: Dict[str, str] = Field(default_factory=dict)
    join_key: str = "unlabeled"
    replica_key: str = ""
    unit: str = ""
    value_kind: Literal["gauge", "counter_delta", "ratio", "histogram_quantile"] = "gauge"
    value: Optional[float] = None
    delta: Optional[float] = None
    numerator: Optional[float] = None
    denominator: Optional[float] = None
    counter_reset_detected: bool = False
    join_status: JoinStatus = "single_series"
    truncated: bool = False
    total_series_count: Optional[int] = None
    retained_series_count: Optional[int] = None
    coverage_status: CoverageStatus = "UNKNOWN"
    sample_timestamps: Tuple[float, ...] = ()
    requested_window: Tuple[str, str]
    status: Literal["SUCCESS", "EMPTY", "UNSUPPORTED", "INVALID_MEASUREMENT", "STALE_TELEMETRY", "TOOL_FAILURE"]
    finding: str
    raw_payload: str = ""


class NormalizedTraceObservation(BaseModel):
    """Typed distributed trace observation anchored to explicit trace_id and incident window."""

    model_config = ConfigDict(frozen=True)

    observation_id: str
    attempt_id: str
    attempt_ids: Tuple[str, ...] = ()
    sample_revision: str = ""
    backend_source: Literal["tempo"] = "tempo"
    target_service: str
    trace_id: str
    trace_timestamp: Optional[float] = None
    bottleneck_service: Optional[str] = None
    bottleneck_operation: Optional[str] = None
    bottleneck_duration_ms: float = 0.0
    error_spans: List[Dict[str, Any]] = Field(default_factory=list)
    spans: List[Dict[str, Any]] = Field(default_factory=list)
    requested_window: Tuple[str, str]
    status: Literal["SUCCESS", "EMPTY", "UNSUPPORTED", "INVALID_MEASUREMENT", "STALE_TELEMETRY", "TOOL_FAILURE"]
    finding: str
    raw_payload: str = ""


class TelemetrySnapshot(BaseModel):
    """Sanitized capture/replay boundary consumable identically across live capture and offline fixtures."""

    schema_version: str = "1.0"
    prometheus: Dict[str, Any] = Field(default_factory=dict)
    tempo: Dict[str, Any] = Field(default_factory=dict)
