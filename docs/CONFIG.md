# Configuration

XPScerpto reads configuration from environment variables or consumer‑provided APIs.

## 1. ISA & Policy
- `XPS_DISABLE_AVX2=1`
- `XPS_DISABLE_AVX512=1`
- `XPS_FORCE_CONSTANT_TIME=1`

## 2. Memory
- `XPS_LOCK_PAGES=1`
- `XPS_MEM_NONTEMPORAL_THRESHOLD=131072`

## 3. Logging & Metrics
- `XPS_METRICS_ENABLE=1`
- `XPS_LOG_LEVEL=info|debug|warn|error`

## 4. PQC
- `XPS_PQC_TRIM_STACK=1`
- `XPS_PQC_PARALLEL=2`

## 5. Build‑time Options (CMake)
- `-DENABLE_ASAN=ON`
- `-DENABLE_UBSAN=ON`
- `-DENABLE_LTO=ON`