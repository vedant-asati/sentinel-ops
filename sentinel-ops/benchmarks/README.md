# Incident decision gate

From `sentinel-ops/`, run the following commands.

```sh
uv run --extra dev python -m pytest tests/test_challenge_gate.py
uv run --extra dev python -m benchmarks.challenge_gate --report /tmp/challenge.json
uv run --extra dev python -m benchmarks.challenge_gate --seed 20261124
```

The gate prints its seed before running. Any wrong status, service, mechanism, or causal citation fails the gate. Candidate crashes, timeouts, malformed output, and invalid schemas count as failures. The JSON report contains each decision, expected result, errors, process duration, and the input for every failure. Duration includes process startup. CI runs a fresh seed and retains the report even when the candidate fails.

## What the first suite measures

The task is to diagnose a **recurring checkout timeout**. To attribute the incident to one mechanism, the suite requires two witnesses within the 60 seconds ending at the incident timestamp. The affected request must contain a timed-out child span on the named dependency and that dependency's corresponding timeout counter must increase. A single failed request can still support a narrower observation about that request. This gate scores only the incident-level causal decision.

Each seed builds 40 trials covering two dependencies and two mechanisms. Each corroborated incident has an equivalent replay with an opaque new ID, paraphrased alert, and reversed serialization order. Other versions change the observations so that a specific cause is no longer supportable. They cover a flat counter, a reset, old metrics, counter growth on the wrong service, a non-finite value, an old request trace, and a missing target trace alongside a plausible distractor. An all-collectors-failed control expects operational failure. The runner shuffles the cases. A correct program can use simple rules.

## Candidate protocol

Use `python -m benchmarks.challenge_gate --seed 17 -- executable arg1` to compare another implementation on identical inputs. Each incident gets a fresh process. Standard input contains one JSON object with an opaque ID, alert text, target service, incident time, trace ID, and telemetry snapshot. The runner retains the family and expected decision. Emit exactly one decision object on standard output and send logs to standard error.

```json
{
  "status": "SUPPORTED_DIAGNOSIS",
  "service": "payment-service",
  "mechanism": "pool_acquisition_timeout",
  "citations": ["prom/payment-service/db_pool_acquire_timeouts_total", "tempo/<affected-trace-id>"]
}
```

The other generated mechanism is `upstream_connect_timeout`, supported by `upstream_connect_timeouts_total` and the matching failed span. Return the minimal causal witnesses in either order. For `INSUFFICIENT_EVIDENCE` and `OPERATIONAL_FAILURE`, return null service and mechanism with an empty citation list. All four fields are required. The built-in bridge uses Sentinel's normal benchmark investigation. It resolves the causal claims' evidence IDs and preserves legacy free-text causes when the implementation supplies no mechanism code. A structured-output mismatch and a false decision are distinguishable in the report.

## Keeping the evaluation honest

The calibration tests run an independent reference using only observable data. They also introduce specific shortcuts and require the grader to reject them for the expected reason. Both a never-diagnose policy and unsupported guesses lose. The original five fixtures remain useful for regression testing.

Fresh seeds vary instances of **public** families. For a release decision, keep independently authored incidents with a trusted evaluator and add them with `--holdout /path/to/reserved.json`. Use a JSON array of records shaped as `{"family": "...", "incident": {...}, "expected": {...}}`. The incident uses the candidate input fields above and the expected decision uses the same four output fields. Reserve whole failure mechanisms or telemetry shapes, use opaque IDs, and agree on acceptable evidence before evaluating candidates. New mechanism codes can be used for these cases. Failing-input reports contain the reserved evidence and answers, so keep those reports with the evaluator.

The subprocess interface separates inputs and bounds run time. Candidates still share the runner's filesystem permissions. Evaluate untrusted submissions in separately isolated workers before using private cases. Passing this suite establishes the declared snapshot decisions for the tested inputs. Live instrumentation, query efficiency, free-text explanations, and usefulness to an operator need independent evaluations.
