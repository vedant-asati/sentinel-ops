"""Seeded checkout incidents. Only Case.incident crosses the candidate boundary."""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import random


SUPPORTED = "SUPPORTED_DIAGNOSIS"
INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
FAILURE = "OPERATIONAL_FAILURE"

# A positive requires both a timeout on the alerted request and corroborating
# counter growth on that dependency. Both mechanisms can occur on either service.
SIGNALS = {
    "pool_acquisition_timeout": ("db.connection.acquire", "db_pool_acquire_timeouts_total"),
    "upstream_connect_timeout": ("rpc.connect", "upstream_connect_timeouts_total"),
}


@dataclass
class Case:
    family: str
    incident: dict
    status: str
    service: str | None = None
    mechanism: str | None = None
    scope: str | None = None
    required_refs: tuple[str, ...] = ()
    localized_service: str | None = None
    localized_operation: str | None = None
    expected_coverage: str | None = None
    required_check_terms: tuple[str, ...] = ()


def shuffled_mapping(mapping, rng):
    items = list(mapping.items())
    rng.shuffle(items)
    return dict(items)


def generate(seed: int) -> list[Case]:
    rng = random.Random(seed)
    cases = []
    for service in ("pricing-service", "payment-service"):
        other = "payment-service" if service == "pricing-service" else "pricing-service"
        for mechanism, (operation, counter) in SIGNALS.items():
            anchor = rng.randrange(1_750_000_000, 1_850_000_000)
            trace_id, decoy_id = (f"{rng.getrandbits(128):032x}" for _ in range(2))
            duration = rng.randrange(1800, 6500)

            def series(before, after, metric_labels=None):
                res_obj = {"status": "SUCCESS", "values": [[anchor - 30, before], [anchor, after]]}
                if metric_labels is not None:
                    return {
                        "status": "SUCCESS",
                        "result": [{"metric": metric_labels, "values": [[anchor - 30, before], [anchor, after]]}],
                    }
                return res_obj

            prom = {}
            for name in (service, other):
                capacity = rng.choice((2, 8, 32, 100))
                metrics = {
                    "db_pool_active": series(capacity, capacity),
                    "db_pool_size": series(capacity, capacity),
                    "latency_p95": series(duration / 1000, duration / 1000),
                }
                for _, metric in SIGNALS.values():
                    initial = rng.randint(3, 500)
                    delta = rng.randint(1, 15) if name == service and metric == counter else 0
                    metrics[metric] = series(initial, initial + delta)
                prom[name] = shuffled_mapping(metrics, rng)

            causal_span_id = f"span_{rng.getrandbits(24):06x}"
            root_span_id = f"root_{rng.getrandbits(24):06x}"
            ok_span_id = f"sib_{rng.getrandbits(24):06x}"
            err_marker = rng.choice(("TimeoutError", "DEADLINE_EXCEEDED"))

            def request_trace(dependency, op):
                return {"status": "SUCCESS", "timestamp": anchor, "spans": [
                    {"span_id": root_span_id, "parent_span_id": None, "service": "checkout-service",
                     "name": "checkout", "duration_ms": duration + 15},
                    {"span_id": ok_span_id, "parent_span_id": root_span_id, "service": other,
                     "name": "fast_lookup", "duration_ms": 12},
                    {"span_id": causal_span_id, "parent_span_id": root_span_id, "service": dependency,
                     "name": op, "duration_ms": duration, "error": err_marker},
                ]}

            decoy_op = next(op for op, _ in SIGNALS.values() if op != operation)
            base = {
                "target_service": "checkout-service",
                "alert_text": f"Repeated checkout timeouts. Affected request trace {trace_id}.",
                "trace_id": trace_id,
                "incident_timestamp": datetime.fromtimestamp(anchor, timezone.utc).isoformat(),
                "mock_telemetry": {
                    "prometheus": shuffled_mapping(prom, rng),
                    "tempo": shuffled_mapping({trace_id: request_trace(service, operation),
                                               decoy_id: request_trace(other, decoy_op)}, rng),
                },
            }
            proof = (f"prom/{service}/{counter}", f"tempo/{trace_id}/{causal_span_id}")

            def add(
                family,
                incident,
                status,
                *,
                loc_svc=None,
                loc_op=None,
                exp_cov=None,
                check_terms=(),
                scope=None,
                svc_override=service,
                mech_override=mechanism,
                refs_override=proof,
            ):
                incident["id"] = f"{rng.getrandbits(96):024x}"
                if status == SUPPORTED:
                    cases.append(Case(
                        family,
                        incident,
                        status,
                        svc_override,
                        mech_override,
                        scope or "affected_request",
                        refs_override,
                        localized_service=loc_svc,
                        localized_operation=loc_op,
                        expected_coverage=exp_cov or "COMPLETE",
                        required_check_terms=tuple(check_terms),
                    ))
                else:
                    cases.append(Case(
                        family,
                        incident,
                        status,
                        localized_service=loc_svc,
                        localized_operation=loc_op,
                        expected_coverage=exp_cov,
                        required_check_terms=tuple(check_terms),
                    ))

            add("corroborated", deepcopy(base), SUPPORTED, loc_svc=service, loc_op=operation)
            reordered = deepcopy(base)
            snapshot = reordered["mock_telemetry"]
            for key in ("prometheus", "tempo"):
                snapshot[key] = dict(reversed(snapshot[key].items()))
            reordered["alert_text"] = f"Repeated 504s on checkout. Investigate request {trace_id}."
            add("renamed-reordered", reordered, SUPPORTED, loc_svc=service, loc_op=operation)

            # Explicit multi-span trace witness (wrong span inside right trace must fail citations)
            multi_span = deepcopy(base)
            multi_span["mock_telemetry"]["tempo"][trace_id]["spans"].append({
                "span_id": f"slow_{rng.getrandbits(16):04x}",
                "parent_span_id": root_span_id,
                "service": service,
                "name": "serialize",
                "duration_ms": 950,
            })
            add("wrong-span-in-correct-trace", multi_span, SUPPORTED, loc_svc=service, loc_op=operation)

            # Truncated 6-pod witness: six pods on `other` dependency (exceeds cap 5 -> coverage=PARTIAL)
            trunc = deepcopy(base)
            six_pods = [
                {"metric": {"service": other, "pod": f"pod-{i}"}, "values": [[anchor - 30, 0.02], [anchor, 0.02]]}
                for i in range(6)
            ]
            six_pods[5]["values"] = [[anchor - 30, 4.9], [anchor, 4.9]]
            trunc["mock_telemetry"]["prometheus"][other]["latency_p95"] = {"status": "SUCCESS", "result": six_pods}
            add("six-pod-truncated-series", trunc, SUPPORTED, loc_svc=service, loc_op=operation, exp_cov="PARTIAL")

            for family in (
                "flat-counter",
                "counter-reset",
                "stale-counter",
                "future-counter",
                "wrong-service",
                "nonfinite",
                "stale-trace",
                "unrelated-trace",
                "missing-requested-trace",
                "collector-outage",
                "service-label-collapse",
                "pod-a-mem-pod-b-flat-restarts",
                "raw-cpu-seconds-overflow",
                "in-range-cumulative-cpu",
                "healthy-target-other-timeout",
                "slow-span-without-timeout",
                "conflicting-retries",
            ):
                incident = deepcopy(base)
                snapshot = incident["mock_telemetry"]
                metrics = snapshot["prometheus"]
                values = metrics[service][counter]["values"]
                loc_svc = None
                loc_op = None
                exp_cov = None
                check_terms: tuple[str, ...] = ()

                if family == "flat-counter":
                    values[-1][1] = values[0][1]
                    loc_svc, loc_op = service, operation
                elif family == "counter-reset":
                    values[-1][1] = 0
                    loc_svc, loc_op = service, operation
                elif family == "stale-counter":
                    for sample in values:
                        sample[0] -= 86400
                    loc_svc, loc_op = service, operation
                elif family == "future-counter":
                    for sample in values:
                        sample[0] += 3600
                    loc_svc, loc_op = service, operation
                elif family == "wrong-service":
                    metrics[other][counter], metrics[service][counter] = (
                        metrics[service][counter], metrics[other][counter])
                    loc_svc, loc_op = service, operation
                elif family == "nonfinite":
                    values[-1][1] = "NaN"
                    loc_svc, loc_op = service, operation
                elif family == "stale-trace":
                    snapshot["tempo"][trace_id]["timestamp"] -= 86400
                elif family == "unrelated-trace":
                    snapshot["tempo"][trace_id] = {"status": "EMPTY"}
                elif family == "missing-requested-trace":
                    missing_id = trace_id
                    extra_id = f"{rng.getrandbits(128):032x}"
                    snapshot["tempo"][extra_id] = deepcopy(snapshot["tempo"].pop(missing_id))
                elif family == "service-label-collapse":
                    cap = rng.choice((4, 16))
                    # Ensure pool_acquisition_timeout op + counter so pool_active (pod-a) vs acquire counter (pod-b) is tested
                    snapshot["tempo"][trace_id]["spans"][-1]["name"] = "db.connection.acquire"
                    metrics[service]["db_pool_active"] = {"status": "SUCCESS", "result": [{"metric": {"service": service, "pod": "pod-a"}, "values": [[anchor - 30, cap], [anchor, cap]]}]}
                    metrics[service]["db_pool_size"] = {"status": "SUCCESS", "result": [{"metric": {"service": service, "pod": "pod-a"}, "values": [[anchor - 30, cap], [anchor, cap]]}]}
                    metrics[service]["db_pool_acquire_timeouts_total"] = {"status": "SUCCESS", "result": [{"metric": {"service": service, "pod": "pod-b"}, "values": [[anchor - 30, 5], [anchor, 18]]}]}
                    loc_svc, loc_op = service, "db.connection.acquire"
                elif family == "pod-a-mem-pod-b-flat-restarts":
                    metrics[service][counter]["values"][-1][1] = metrics[service][counter]["values"][0][1]
                    snapshot["tempo"][trace_id] = {
                        "status": "SUCCESS",
                        "timestamp": anchor,
                        "spans": [{"span_id": "root", "parent_span_id": None, "service": "checkout-service", "name": "checkout", "duration_ms": 900}],
                    }
                    metrics["cart-service"] = {
                        "memory_usage": {"status": "SUCCESS", "result": [{"metric": {"service": "cart-service", "pod": "cart-a"}, "values": [[anchor - 30, 0.96], [anchor, 0.99]]}]},
                        "container_restarts": {"status": "SUCCESS", "result": [{"metric": {"service": "cart-service", "pod": "cart-b"}, "values": [[anchor - 30, 3], [anchor, 3]]}]},
                    }
                    loc_svc, loc_op = "checkout-service", "checkout"
                elif family in ("raw-cpu-seconds-overflow", "in-range-cumulative-cpu"):
                    cpu_val = 120.0 if family == "raw-cpu-seconds-overflow" else 0.4
                    metrics[service][counter]["values"][-1][1] = metrics[service][counter]["values"][0][1]
                    snapshot["tempo"][trace_id] = {
                        "status": "SUCCESS",
                        "timestamp": anchor,
                        "spans": [
                            {"span_id": "root", "parent_span_id": None, "service": "checkout-service", "name": "checkout", "duration_ms": duration},
                            {"span_id": "c1", "parent_span_id": "root", "service": "pricing-service", "name": "compute_quote", "duration_ms": duration - 20},
                        ],
                    }
                    metrics["pricing-service"]["cpu_saturation"] = {
                        "status": "SUCCESS",
                        "promql": 'container_cpu_usage_seconds_total{container="pricing-service"}',
                        "result": [{"metric": {"container": "pricing-service"}, "values": [[anchor - 30, cpu_val], [anchor, cpu_val]]}],
                    }
                    loc_svc, loc_op = "pricing-service", "compute_quote"
                elif family == "healthy-target-other-timeout":
                    snapshot["tempo"][trace_id] = {
                        "status": "SUCCESS",
                        "timestamp": anchor,
                        "spans": [
                            {"span_id": "root", "parent_span_id": None, "service": "checkout-service", "name": "checkout", "duration_ms": 45},
                            {"span_id": "ok1", "parent_span_id": "root", "service": other, "name": "fast_lookup", "duration_ms": 30},
                        ],
                    }
                    loc_svc, loc_op = other, "fast_lookup"
                elif family == "slow-span-without-timeout":
                    metrics[service][counter] = {"status": "SUCCESS", "result": [{"metric": {"pod": "pay-0"}, "values": [[anchor - 30, 2], [anchor, 15]]}]}
                    snapshot["tempo"][trace_id] = {
                        "status": "SUCCESS",
                        "timestamp": anchor,
                        "spans": [
                            {"span_id": "root", "parent_span_id": None, "service": "checkout-service", "name": "checkout", "duration_ms": 2400},
                            {"span_id": "rcpt", "parent_span_id": "root", "service": other, "name": "render_receipt", "duration_ms": 2350},
                        ],
                    }
                    loc_svc, loc_op = other, "render_receipt"
                    check_terms = ("render_receipt", service)
                elif family == "conflicting-retries":
                    metrics[service][counter] = {
                        "status": "SUCCESS",
                        "result": [
                            {"metric": {"pod": "p-0"}, "values": [[anchor - 30, 5], [anchor, 19]]},
                            {"metric": {"pod": "p-0"}, "values": [[anchor - 30, 5], [anchor, 5]]},
                        ],
                    }
                    loc_svc, loc_op = service, operation
                else:
                    for signals in metrics.values():
                        for key in signals:
                            signals[key] = {"status": "TOOL_FAILURE"}
                    snapshot["tempo"] = {key: {"status": "TOOL_FAILURE"} for key in snapshot["tempo"]}

                add(
                    family,
                    incident,
                    FAILURE if family == "collector-outage" else INSUFFICIENT,
                    loc_svc=loc_svc,
                    loc_op=loc_op,
                    exp_cov=exp_cov,
                    check_terms=check_terms,
                )
    rng.shuffle(cases)
    return cases
