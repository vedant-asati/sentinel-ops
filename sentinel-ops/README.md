# Sentinel-Ops Platform

Autonomous AI Site Reliability Engineering (AI SRE) and Root Cause Analysis (RCA) platform.

## Architecture Highlights
- **Evidence-Backed Investigation:** Collects, sanitizes, and indexes observations (`EV-xxx`) from Prometheus and Tempo.
- **Strict Terminal Outcomes:** Distinguishes competing causes (`SUPPORTED_DIAGNOSIS`) or explicitly abstains when signal is inconclusive (`INSUFFICIENT_EVIDENCE`).
- **Adversarial Falsification Reviewer:** Eliminates confirmation bias by subjecting draft claims to a fresh-context skeptic prosecutor.
- **Server-Enforced Telemetry Bounds:** Zero prompt-injection exposure; query intervals are anchored to $T_{\text{incident}}$.
- **Reverse Blast Radius Traversal:** Upstream caller dependency traversal to calculate blast radius impact.
