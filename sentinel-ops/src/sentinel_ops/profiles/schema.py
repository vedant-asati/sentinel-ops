"""Versioned SystemProfile schemas separating deployment config from tested rule logic."""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Literal, Optional, Set, Tuple
import networkx as nx
from pydantic import BaseModel, Field, model_validator


_CUMULATIVE_SUFFIXES = ("_total", "_seconds_total", "_bytes_total", "_timeouts")
_KNOWN_CUMULATIVE_NAMES = {"packet_drops", "dropped_packets", "timeouts", "timeout_drops", "connection_drops", "restarts", "container_restarts"}
_RATE_CALL_RE = re.compile(r"\b(?:rate|irate|increase)\s*\([^)]*\)", re.IGNORECASE)
_RATE_EXPR_RE = re.compile(r"\b(rate|irate|increase)\s*\(", re.IGNORECASE)

_DURATION_MULTIPLIERS: Dict[str, float] = {
    "": 1.0,
    "s": 1.0,
    "sec": 1.0,
    "secs": 1.0,
    "second": 1.0,
    "seconds": 1.0,
    "ms": 1e-3,
    "msec": 1e-3,
    "millisecond": 1e-3,
    "milliseconds": 1e-3,
    "us": 1e-6,
    "usec": 1e-6,
    "microsecond": 1e-6,
    "microseconds": 1e-6,
    "ns": 1e-9,
    "nsec": 1e-9,
    "nanosecond": 1e-9,
    "nanoseconds": 1e-9,
}


def normalize_duration_to_seconds(value: float, unit: str = "") -> float:
    """Converts a duration measurement in s/ms/us/ns to canonical seconds."""
    mult = _DURATION_MULTIPLIERS.get((unit or "").strip().lower(), 1.0)
    return float(value) * mult


def is_cumulative_counter_metric(
    promql: str = "",
    signal_name: str = "",
    labels: Optional[Dict[str, str]] = None,
    value_kind: Optional[str] = None,
) -> bool:
    """Returns True if metadata/PromQL indicates an un-normalized cumulative counter."""
    lbls = labels or {}
    if str(lbls.get("__type__", "")).lower() == "counter" or str(lbls.get("metric_kind", "")).lower() == "counter":
        if not promql or not _RATE_EXPR_RE.search(promql):
            return True
    name_to_check = str(lbls.get("__name__") or signal_name or "").strip().lower()
    if promql:
        # Remove wrapped rate()/irate()/increase() subexpressions before inspecting bare tokens
        unwrapped = _RATE_CALL_RE.sub(" ", promql)
        tokens = re.findall(r"[A-Za-z_:][A-Za-z0-9_:]*", unwrapped)
        if any(t.lower().endswith(_CUMULATIVE_SUFFIXES) or t.lower() in _KNOWN_CUMULATIVE_NAMES for t in tokens):
            return True
    if value_kind != "gauge":
        if (name_to_check.endswith(_CUMULATIVE_SUFFIXES) or name_to_check in _KNOWN_CUMULATIVE_NAMES) and (
            not promql or not _RATE_EXPR_RE.search(promql)
        ):
            return True
    return False


class SignalMapping(BaseModel):
    """Maps a canonical rule concept (e.g. pool_active) to native telemetry instrumentation."""

    logical_signal: str
    metric_name: str
    promql_template: str
    unit: str = ""
    value_kind: Literal["gauge", "counter_delta", "ratio", "histogram_quantile"] = "gauge"
    capacity_signal: Optional[str] = None
    saturation_threshold: Optional[float] = None

    @model_validator(mode="after")
    def _validate_signal_semantics(self) -> "SignalMapping":
        try:
            self.promql_template.format(service="svc")
        except (KeyError, ValueError, IndexError) as exc:
            raise ValueError(
                f"Signal '{self.logical_signal}' has invalid promql_template format '{self.promql_template}': {exc}"
            ) from exc
        if self.saturation_threshold is not None:
            thr = float(self.saturation_threshold)
            if math.isnan(thr) or math.isinf(thr) or thr < 0.0:
                raise ValueError(
                    f"Signal '{self.logical_signal}' saturation_threshold must be finite and non-negative, got {self.saturation_threshold}"
                )
            ratio_like = (
                self.unit == "ratio"
                or self.value_kind == "ratio"
                or self.logical_signal in ("pool_active", "cpu_utilization", "memory_utilization", "error_rate")
            )
            if ratio_like and thr > 1.0:
                raise ValueError(
                    f"Ratio/utilization signal '{self.logical_signal}' saturation_threshold must be <= 1.0, got {thr}"
                )
        return self


class ServiceSpec(BaseModel):
    """Service identity, dependencies, and default probes inside a profiled system."""

    name: str
    role: Literal["ingress", "api", "worker", "datastore", "service"] = "service"
    depends_on: List[str] = Field(default_factory=list)
    metrics: List[str] = Field(default_factory=list)
    replica_labels: List[str] = Field(
        default_factory=lambda: ["pod", "instance", "container"]
    )
    replica_join_labels: List[str] = Field(
        default_factory=lambda: ["pod", "instance", "container"]
    )

    def resolved_replica_labels(self) -> Tuple[str, ...]:
        """Returns declared true replica identity labels, excluding fleet-level service/app tags."""
        raw = self.replica_labels or self.replica_join_labels
        filtered = [k for k in raw if k not in ("service", "app")]
        return tuple(filtered) if filtered else ("pod", "instance", "container")


class TraceContract(BaseModel):
    """Maps distributed trace span operations and error markers to rule mechanisms."""

    operation_aliases: Dict[str, List[str]] = Field(default_factory=dict)
    timeout_error_markers: List[str] = Field(default_factory=lambda: ["TimeoutError", "DEADLINE_EXCEEDED"])


class RulePreflightResult(BaseModel):
    """Readiness status of a single diagnostic rule under a given SystemProfile."""

    rule_id: str
    status: Literal["SUPPORTED", "LOCALIZATION_ONLY", "UNSUPPORTED"]
    missing_signals: List[str] = Field(default_factory=list)
    missing_operations: List[str] = Field(default_factory=list)
    notes: str = ""


RULE_REQUIREMENTS: Dict[str, Tuple[Tuple[str, ...], bool]] = {
    # rule_id -> (required logical signals, supports trace localization fallback)
    "pool_acquisition_timeout": (("pool_active", "pool_capacity", "pool_acquire_timeouts"), True),
    "upstream_connect_timeout": (("upstream_connect_timeouts",), True),
    "cpu_contention": (("latency_p95", "cpu_utilization"), True),
    "memory_leak_oomkill": (("memory_utilization", "container_restarts"), False),
}


class SystemProfile(BaseModel):
    """Versioned system profile loaded from configuration without Python code changes."""

    profile_id: str
    version: str = "1.0.0"
    environment: str = "default"
    services: Dict[str, ServiceSpec]
    signals: Dict[str, SignalMapping]
    trace_contract: TraceContract = Field(default_factory=TraceContract)
    enabled_rules: List[str] = Field(default_factory=list)
    check_templates: Dict[str, List[str]] = Field(default_factory=dict)
    runbook_hints: Dict[str, str] = Field(default_factory=dict)
    postmortems: List[Dict[str, Any]] = Field(default_factory=list)
    telemetry_auth: Dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_topology_dag(self) -> "SystemProfile":
        for svc_name, spec in self.services.items():
            for dep in spec.depends_on:
                if dep not in self.services:
                    raise ValueError(
                        f"Service '{svc_name}' depends on undefined service '{dep}' in profile '{self.profile_id}'."
                    )
        g = self.build_service_graph()
        if not nx.is_directed_acyclic_graph(g):
            raise ValueError(
                f"Service topology for profile '{self.profile_id}' contains a dependency cycle; depends_on must form a DAG."
            )
        return self

    def resolve_service_names(self) -> Tuple[str, ...]:
        return tuple(self.services.keys())

    def resolve_dependencies(self, target_service: str) -> List[str]:
        spec = self.services.get(target_service)
        if spec and spec.depends_on:
            return list(spec.depends_on)
        return [target_service] if target_service in self.services else []

    def resolve_signal(self, name_or_logical: str) -> Optional[SignalMapping]:
        if name_or_logical in self.signals:
            return self.signals[name_or_logical]
        for mapping in self.signals.values():
            if mapping.metric_name == name_or_logical:
                return mapping
        return None

    def to_promql_templates(self) -> Dict[str, str]:
        templates: Dict[str, str] = {}
        for logical, mapping in self.signals.items():
            templates[logical] = mapping.promql_template
            templates[mapping.metric_name] = mapping.promql_template
        return templates

    def build_service_graph(self) -> nx.DiGraph:
        g = nx.DiGraph()
        for svc_name, spec in self.services.items():
            g.add_node(svc_name)
            for dep in spec.depends_on:
                g.add_edge(svc_name, dep)
        return g

    def validate_mappings(self) -> List[str]:
        """Stage 1 preflight: validates declared signal semantics, replica keys, and trace contracts."""
        warnings: List[str] = []
        for logical, mapping in self.signals.items():
            is_ratio = mapping.unit == "ratio" or mapping.value_kind in ("gauge", "ratio")
            if is_ratio and mapping.unit == "ratio" and is_cumulative_counter_metric(mapping.promql_template, mapping.metric_name):
                warnings.append(
                    f"Signal '{logical}' ({mapping.metric_name}) declares unit='ratio' over un-rated cumulative query '{mapping.promql_template}'; "
                    "add rate()/capacity normalization or it will be rejected as INVALID_MEASUREMENT."
                )
            if mapping.capacity_signal and mapping.capacity_signal not in self.signals and all(
                s.metric_name != mapping.capacity_signal for s in self.signals.values()
            ):
                warnings.append(
                    f"Signal '{logical}' references capacity_signal='{mapping.capacity_signal}' which is not declared in profile.signals."
                )
        for svc_name, spec in self.services.items():
            if not spec.resolved_replica_labels():
                warnings.append(f"Service '{svc_name}' has no replica identity labels configured.")
        return warnings

    def preflight(self, available_signals: Optional[Set[str]] = None) -> Dict[str, RulePreflightResult]:
        """Evaluates which diagnostic rules can run given mapped and live/available signals."""
        declared = set(self.signals.keys()) | {m.metric_name for m in self.signals.values()}
        effective = declared if available_signals is None else (declared & available_signals)
        results: Dict[str, RulePreflightResult] = {}

        for rule_id in self.enabled_rules:
            req_signals, supports_loc = RULE_REQUIREMENTS.get(rule_id, ((), False))
            missing = []
            for sig in req_signals:
                mapping = self.signals.get(sig)
                if mapping is None or (mapping.logical_signal not in effective and mapping.metric_name not in effective):
                    missing.append(sig)
            missing_ops = []
            if rule_id in ("pool_acquisition_timeout", "upstream_connect_timeout"):
                if not self.trace_contract.operation_aliases.get(rule_id):
                    missing_ops.append(rule_id)

            if not missing and not missing_ops:
                results[rule_id] = RulePreflightResult(
                    rule_id=rule_id,
                    status="SUPPORTED",
                    notes="All required signals and trace operation mappings present.",
                )
            elif supports_loc and self.signals.get("latency_p95") is not None:
                results[rule_id] = RulePreflightResult(
                    rule_id=rule_id,
                    status="LOCALIZATION_ONLY",
                    missing_signals=missing,
                    missing_operations=missing_ops,
                    notes="Latency/trace localization available, but causal sub-mechanism counters unavailable.",
                )
            else:
                results[rule_id] = RulePreflightResult(
                    rule_id=rule_id,
                    status="UNSUPPORTED",
                    missing_signals=missing,
                    missing_operations=missing_ops,
                    notes="Required instrumentation signals not mapped or unavailable.",
                )
        return results
