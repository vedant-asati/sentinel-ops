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
    required_refs: tuple[str, ...] = ()


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

            def series(before, after):
                return {"status": "SUCCESS", "values": [[anchor - 30, before], [anchor, after]]}

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

            def request_trace(dependency, op):
                return {"status": "SUCCESS", "timestamp": anchor, "spans": [
                    {"span_id": "root", "parent_span_id": None, "service": "checkout-service",
                     "name": "checkout", "duration_ms": duration + 15},
                    {"span_id": "child", "parent_span_id": "root", "service": dependency,
                     "name": op, "duration_ms": duration, "error": "TimeoutError"},
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
            proof = (f"prom/{service}/{counter}", f"tempo/{trace_id}")

            def add(family, incident, status):
                incident["id"] = f"{rng.getrandbits(96):024x}"
                if status == SUPPORTED:
                    cases.append(Case(family, incident, status, service, mechanism, proof))
                else:
                    cases.append(Case(family, incident, status))

            add("corroborated", deepcopy(base), SUPPORTED)
            reordered = deepcopy(base)
            snapshot = reordered["mock_telemetry"]
            for key in ("prometheus", "tempo"):
                snapshot[key] = dict(reversed(snapshot[key].items()))
            reordered["alert_text"] = f"Repeated 504s on checkout. Investigate request {trace_id}."
            add("renamed-reordered", reordered, SUPPORTED)

            for family in ("flat-counter", "counter-reset", "stale-counter", "wrong-service",
                           "nonfinite", "stale-trace", "unrelated-trace", "collector-outage"):
                incident = deepcopy(base)
                snapshot = incident["mock_telemetry"]
                metrics = snapshot["prometheus"]
                values = metrics[service][counter]["values"]
                if family == "flat-counter":
                    values[-1][1] = values[0][1]
                elif family == "counter-reset":
                    values[-1][1] = 0
                elif family == "stale-counter":
                    for sample in values:
                        sample[0] -= 86400
                elif family == "wrong-service":
                    metrics[other][counter], metrics[service][counter] = (
                        metrics[service][counter], metrics[other][counter])
                elif family == "nonfinite":
                    values[-1][1] = "NaN"
                elif family == "stale-trace":
                    snapshot["tempo"][trace_id]["timestamp"] -= 86400
                elif family == "unrelated-trace":
                    snapshot["tempo"][trace_id] = {"status": "EMPTY"}
                else:
                    for signals in metrics.values():
                        for key in signals:
                            signals[key] = {"status": "TOOL_FAILURE"}
                    snapshot["tempo"] = {key: {"status": "TOOL_FAILURE"} for key in snapshot["tempo"]}
                add(family, incident, FAILURE if family == "collector-outage" else INSUFFICIENT)
    rng.shuffle(cases)
    return cases
