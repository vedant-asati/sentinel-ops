"""Versioned SystemProfile schemas separating deployment config from tested rule logic."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Set, Tuple
import networkx as nx
from pydantic import BaseModel, Field


class SignalMapping(BaseModel):
    """Maps a canonical rule concept (e.g. pool_active) to native telemetry instrumentation."""

    logical_signal: str
    metric_name: str
    promql_template: str
    unit: str = ""
    value_kind: Literal["gauge", "counter_delta", "ratio", "histogram_quantile"] = "gauge"
    capacity_signal: Optional[str] = None
    saturation_threshold: Optional[float] = None


class ServiceSpec(BaseModel):
    """Service identity, dependencies, and default probes inside a profiled system."""

    name: str
    role: Literal["ingress", "api", "worker", "datastore", "service"] = "service"
    depends_on: List[str] = Field(default_factory=list)
    metrics: List[str] = Field(default_factory=list)
    replica_join_labels: List[str] = Field(
        default_factory=lambda: ["pod", "instance", "container", "app", "service"]
    )


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
