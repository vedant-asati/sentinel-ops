import json
from pathlib import Path
import pytest

from sentinel_ops.agents.adversarial import adversarial_reviewer_node
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem, InvestigationState
from sentinel_ops.agents.synthesizer import format_incident_brief
from sentinel_ops.profiles.registry import get_profile
from sentinel_ops.rules.engine import _pairs_same_replica_or_fleet, evaluate_all_rules
from sentinel_ops.telemetry.models import NormalizedMetricObservation, NormalizedTraceObservation


# ==============================================================================
# TARGET 1: Break the Rule Engine (rules/engine.py)
# ==============================================================================

def test_pathological_replica_label_join_redundant_label_flips_verdict():
    """VULNERABILITY PROOF 1.1A: Adding a redundant label (e.g. 'job=payment') to one

    metric flips _pairs_same_replica_or_fleet from True to False, completely flipping
    the root-cause verdict from is_sufficient=True to is_sufficient=False (Abstain).
    """
    prof = get_profile("checkout-demo")

    obs_pool = NormalizedMetricObservation(
        observation_id="OBS-POOL",
        attempt_id="att-1",
        finding="Pool 98% saturated",
        backend_source="prometheus",
        service="payment-service",
        signal_name="pool_active",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        value=0.98,
        join_key="service=payment-service",
        replica_key="",
        join_status="single_series",
    )

    # 1. Matching join_key -> Successfully pairs and certifies root cause
    obs_wait_matching = NormalizedMetricObservation(
        observation_id="OBS-WAIT",
        attempt_id="att-2",
        finding="Pool wait timeouts spiked +5",
        backend_source="prometheus",
        service="payment-service",
        signal_name="pool_acquire_timeouts",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        delta=5.0,
        sample_timestamps=(1795530720.0, 1795530735.0),
        join_key="service=payment-service",
        replica_key="",
        join_status="single_series",
    )

    ok_matching, _ = _pairs_same_replica_or_fleet(obs_pool, obs_wait_matching)
    res_matching = evaluate_all_rules(
        profile=prof,
        observations=[obs_pool, obs_wait_matching],
        enabled_only=["pool_acquisition_timeout"],
    )
    assert ok_matching is True
    assert res_matching.is_sufficient is True
    assert res_matching.winning_rule == "pool_acquisition_timeout"

    # 2. Add redundant label 'job=payment' to obs_wait -> Join fails and evaluation flips to False!
    obs_wait_redundant = obs_wait_matching.model_copy(
        update={"join_key": "job=payment|service=payment-service"}
    )
    ok_redundant, _ = _pairs_same_replica_or_fleet(obs_pool, obs_wait_redundant)
    res_redundant = evaluate_all_rules(
        profile=prof,
        observations=[obs_pool, obs_wait_redundant],
        enabled_only=["pool_acquisition_timeout"],
    )

    # INVARIANT HELD: Benign redundant fleet label 'job=payment' does NOT break fleet alignment
    assert ok_redundant is True
    assert res_redundant.is_sufficient is True
    assert res_redundant.winning_rule == "pool_acquisition_timeout"


def test_cross_service_replica_collision_without_service_check():
    """Verify _pairs_same_replica_or_fleet rejects same replica_key across distinct services."""
    obs_cart = NormalizedMetricObservation(
        observation_id="OBS-CART",
        attempt_id="att-1",
        finding="Cart memory 95%",
        backend_source="prometheus",
        service="cart-service",
        signal_name="memory_utilization",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        value=0.95,
        join_key="pod=worker-1",
        replica_key="pod=worker-1",
        join_status="single_series",
    )

    obs_payment = NormalizedMetricObservation(
        observation_id="OBS-PAYM",
        attempt_id="att-2",
        finding="Payment restarts delta +2",
        backend_source="prometheus",
        service="payment-service",  # COMPLETELY DIFFERENT SERVICE!
        signal_name="container_restarts",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        delta=2.0,
        sample_timestamps=(1795530720.0, 1795530735.0),
        join_key="pod=worker-1",
        replica_key="pod=worker-1",
        join_status="single_series",
    )

    ok, _ = _pairs_same_replica_or_fleet(obs_cart, obs_payment)

    # INVARIANT HELD: Two observations from different services NEVER pair
    assert ok is False


def test_cumulative_counter_cross_pod_memory_leak_certification():
    """Verify unlabeled/cross-pod memory + restarts WITHOUT same replica_key never certifies."""
    prof = get_profile("checkout-demo")

    # Pod A at 99% memory (fleet level / unlabeled)
    obs_mem = NormalizedMetricObservation(
        observation_id="OBS-MEM-A",
        attempt_id="att-1",
        finding="cart-service memory usage 99%",
        backend_source="prometheus",
        service="cart-service",
        signal_name="memory_utilization",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        value=0.99,
        join_key="unlabeled",
        replica_key="",
        join_status="single_series",
    )

    # Pod B cumulative restart count delta +3
    obs_restart = NormalizedMetricObservation(
        observation_id="OBS-RESTART-B",
        attempt_id="att-2",
        finding="cart-service restarts delta +3",
        backend_source="prometheus",
        service="cart-service",
        signal_name="container_restarts",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        delta=3.0,
        sample_timestamps=(1795530720.0, 1795530735.0),
        join_key="unlabeled",
        replica_key="",
        join_status="single_series",
    )

    res = evaluate_all_rules(
        profile=prof,
        observations=[obs_mem, obs_restart],
        enabled_only=["memory_pressure_restarts", "memory_leak_oomkill"],
    )

    # INVARIANT HELD: Blocks cross-pod/unlabeled memory leak certification
    assert res.is_sufficient is False


def test_signal_dimension_and_range_distortion_12000_percent_cpu():
    """Verify raw cumulative CPU seconds (e.g. 120s, unit='seconds') is rejected for ratio cpu_contention."""
    prof = get_profile("checkout-demo")

    obs_cpu = NormalizedMetricObservation(
        observation_id="OBS-CPU",
        attempt_id="att-1",
        finding="pricing-service container_cpu_usage_seconds_total observed at 120.0s",
        backend_source="prometheus",
        service="pricing-service",
        signal_name="cpu_utilization",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        value=120.0,  # 120 seconds!
        unit="seconds",
        join_key="unlabeled",
        replica_key="",
        join_status="single_series",
    )

    obs_lat = NormalizedMetricObservation(
        observation_id="OBS-LAT",
        attempt_id="att-2",
        finding="pricing-service latency_p95 spiked critically at 2.000s",
        backend_source="prometheus",
        service="pricing-service",
        signal_name="latency_p95",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        value=2.0,
        unit="seconds",
        join_key="unlabeled",
        replica_key="",
        join_status="single_series",
    )

    res = evaluate_all_rules(
        profile=prof,
        observations=[obs_cpu, obs_lat],
        enabled_only=["cpu_contention"],
    )

    # INVARIANT HELD: Rejects raw seconds CPU measurement for ratio rule
    assert res.is_sufficient is False


# ==============================================================================
# TARGET 2: Adversarial Verifier / Reviewer (agents/adversarial.py)
# ==============================================================================

def test_unsupported_mechanism_slips_past_independent_verifier_into_brief():
    """Verify adversarial_reviewer_node FAILS CLOSED on unknown/unverified mechanisms."""
    obs = NormalizedMetricObservation(
        observation_id="OBS-AUTH-001",
        attempt_id="att-1",
        finding="auth-service response latency normal at 0.05s",
        backend_source="prometheus",
        service="auth-service",
        signal_name="latency_p95",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        value=0.05,
        join_key="unlabeled",
        replica_key="",
        join_status="single_series",
    )

    ev = EvidenceItem(
        id="EV-auth-001",
        backend_source="prometheus",
        query_string="auth_latency",
        query_params={"service": "auth-service", "observation_id": "OBS-AUTH-001"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="latency_p95",
        finding="auth-service response latency normal at 0.05s",
        raw_payload="",
        status="SUCCESS",
    )

    claims = [
        AtomicClaim(
            claim_id="CL-001",
            statement="auth-service crypto_miner_injected is the root cause of degradation.",
            claim_type="root_cause",
            claim_scope="service_fleet",
            cited_evidence_ids=["EV-auth-001"],
        ),
        AtomicClaim(
            claim_id="CL-002",
            statement="auth-service response latency normal at 0.05s",
            claim_type="mechanism",
            claim_scope="service_fleet",
            cited_evidence_ids=["EV-auth-001"],
        ),
    ]

    state = InvestigationState(
        incident_id="INC-UNSUPPORTED-001",
        alert_text="Security alert",
        incident_timestamp="2026-11-24T14:32:00Z",
        target_service="auth-service",
        mechanism="crypto_miner_injected",
        evidence=[ev],
        observations=[obs],
        structured_claims=claims,
    )

    res = adversarial_reviewer_node(state)
    verdict = res["adversarial_verdict"]

    # INVARIANT HELD: Verifier rejects arbitrary unsupported mechanism!
    from sentinel_ops.agents.adversarial import route_adversarial_review
    assert verdict.all_claims_supported is False
    assert verdict.confidence < 0.5
    assert route_adversarial_review(state.model_copy(update={"adversarial_verdict": verdict, "adversarial_iterations": 1})) == "synthesizer"


def test_verifier_contradiction_blindness_cherry_picked_consensus():
    """VULNERABILITY PROOF 2.2: adversarial_reviewer_node only checks conflicts across

    identical join_keys. A cherry-picked pod counter spike succeeds with 1.0 confidence
    even when contradictory observations with counter_reset_detected or zero delta exist
    in state.observations under different join_keys.
    """
    # 1. Cherry-picked pod with counter spike
    obs_cnt = NormalizedMetricObservation(
        observation_id="OBS-CNT-1",
        attempt_id="att-1",
        finding="payment-service upstream connect timeouts spiked +1",
        backend_source="prometheus",
        service="payment-service",
        signal_name="upstream_connect_timeouts",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        delta=1.0,
        sample_timestamps=(1795530720.0, 1795530735.0),
        join_key="pod=payment-1",
        replica_key="pod=payment-1",
        join_status="single_series",
    )

    # 2. Uncited contradictory counter on payment-service with counter_reset_detected!
    obs_cnt_contra = NormalizedMetricObservation(
        observation_id="OBS-CNT-2",
        attempt_id="att-2",
        finding="payment-service upstream connect timeouts flat at 0 with reset",
        backend_source="prometheus",
        service="payment-service",
        signal_name="upstream_connect_timeouts",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        delta=0.0,
        counter_reset_detected=True,
        sample_timestamps=(1795530720.0, 1795530735.0),
        join_key="pod=payment-2",
        replica_key="pod=payment-2",
        join_status="single_series",
    )

    obs_trace = NormalizedTraceObservation(
        observation_id="OBS-TRACE-1",
        attempt_id="att-3",
        trace_id="trace-001",
        target_service="checkout-service",
        finding="TimeoutError in payment-service on rpc.connect",
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        bottleneck_service="payment-service",
        bottleneck_operation="rpc.connect",
        bottleneck_duration_ms=5000.0,
        error_spans=[{
            "span_id": "sp-1",
            "service": "payment-service",
            "name": "rpc.connect",
            "error": "TimeoutError",
            "duration_ms": 5000.0,
        }],
    )

    ev_cnt = EvidenceItem(
        id="EV-CNT-1",
        backend_source="prometheus",
        query_string="connect_timeouts",
        query_params={"service": "payment-service", "observation_id": "OBS-CNT-1"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="upstream_connect_timeouts",
        finding="payment-service upstream connect timeouts spiked +1",
        raw_payload="",
        status="SUCCESS",
    )

    ev_trace = EvidenceItem(
        id="EV-TRACE-1",
        backend_source="tempo",
        query_string="trace-001",
        query_params={"target_service": "checkout-service", "trace_id": "trace-001", "observation_id": "OBS-TRACE-1"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="span_waterfall",
        finding="TimeoutError in payment-service on rpc.connect",
        raw_payload="",
        status="SUCCESS",
    )

    claims = [
        AtomicClaim(
            claim_id="CL-001",
            statement="payment-service on trace trace-001 upstream_connect_timeout is the root cause of degradation.",
            claim_type="root_cause",
            claim_scope="affected_request",
            claim_subject="payment-service on trace trace-001",
            cited_evidence_ids=["EV-CNT-1", "EV-TRACE-1"],
        ),
        AtomicClaim(
            claim_id="CL-002",
            statement="payment-service upstream connect timeouts spiked +1",
            claim_type="mechanism",
            claim_scope="affected_request",
            claim_subject="payment-service on trace trace-001",
            cited_evidence_ids=["EV-CNT-1", "EV-TRACE-1"],
        ),
    ]

    state = InvestigationState(
        incident_id="INC-BYPASS-001",
        alert_text="Timeout alert",
        incident_timestamp="2026-11-24T14:32:00Z",
        target_service="checkout-service",
        trace_id="trace-001",
        mechanism="upstream_connect_timeout",
        evidence=[ev_cnt, ev_trace],
        observations=[obs_cnt, obs_cnt_contra, obs_trace],
        structured_claims=claims,
    )

    res = adversarial_reviewer_node(state)
    verdict = res["adversarial_verdict"]

    # BROKEN INVARIANT: Contradictory observation in state is ignored; verifier yields 1.0 confidence!
    assert verdict.all_claims_supported is True
    assert verdict.confidence == 1.00
