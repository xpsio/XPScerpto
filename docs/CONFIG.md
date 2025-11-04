# Configuration

<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Table of Contents](#table-of-contents)
- [1. ISA & Policy](#1-isa--policy)
- [2. Memory](#2-memory)
- [3. Logging & Metrics](#3-logging--metrics)
- [4. PQC](#4-pqc)
- [5. Build‑time Options (CMake)](#5-buildtime-options-cmake)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [1. ISA & Policy](#1-isa--policy)
- [2. Memory](#2-memory)
- [3. Logging & Metrics](#3-logging--metrics)
- [4. PQC](#4-pqc)
- [5. Build‑time Options (CMake)](#5-buildtime-options-cmake)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [1. ISA & Policy](#1-isa--policy)
- [2. Memory](#2-memory)
- [3. Logging & Metrics](#3-logging--metrics)
- [4. PQC](#4-pqc)
- [5. Build‑time Options (CMake)](#5-buildtime-options-cmake)
<!-- TOC-END -->


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