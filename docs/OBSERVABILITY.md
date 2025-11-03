# Observability

Lightweight metrics and logs help detect regressions and incidents without leaking secrets.

## 1. Metrics

- Counters: total operations per primitive
- Gauges: active keys, locked pages
- Histograms: latency buckets for seal/open

## 2. Logging

- Structured logs: JSON lines optional
- Redact secrets by default
- Error codes from the central taxonomy

## 3. Export

- Minimal HTTP pull endpoint for Prometheus (optional)
- Disable in builds where telemetry is disallowed