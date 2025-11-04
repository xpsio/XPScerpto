# Observability

<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Table of Contents](#table-of-contents)
- [1. Metrics](#1-metrics)
- [2. Logging](#2-logging)
- [3. Export](#3-export)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [1. Metrics](#1-metrics)
- [2. Logging](#2-logging)
- [3. Export](#3-export)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [1. Metrics](#1-metrics)
- [2. Logging](#2-logging)
- [3. Export](#3-export)
<!-- TOC-END -->


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