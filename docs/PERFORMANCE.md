# Performance

This document captures methodology, knobs, and reference numbers to tune XPScerpto deployments.

## 1. Methodology

- **Hardware**: disclose CPU model, ISA, cores, memory
- **Build**: Release + `-fno-exceptions` where possible; LTO optional
- **Warmup**: ignore first N runs; median over M runs
- **Sanitizers**: never for final numbers
- **Affinity**: pin threads to reduce jitter

## 2. Dispatch Controls

- Enable/disable ISAs via env/config
- Nontemporal copy thresholds for big buffers
- Size cut‑offs for short vs long message kernels

## 3. Reference Throughput (illustrative)

| Primitive | Portable | AVX2 | NEON |
|---|---:|---:|---:|
| SHA‑384 (MiB/s) | ~800 | ~1700 | ~1200 |
| BLAKE3‑256 (MiB/s) | ~3500 | ~5500 | ~4200 |
| AES‑GCM 128 (MiB/s) | ~900 | ~2100 | ~1500 |

> **Note**: Replace with your measured numbers. Keep raw logs in `perf/` and plot with your preferred tooling.

## 4. Memory & Copy

- `xps.memory::memcpy` with autotune and ISA selection improves bulk moves
- Avoid overlap or use `memmove` emulation when needed
- Provide knobs for prefetch distances and blocking

## 5. PQC Notes

- Falcon/Dilithium performance depends on FFT/NTT backends
- Keep stack use monitored; batch sign/verify interfaces can improve locality

## 6. Regression Guardrails

- Keep KATs and micro‑bench in CI (reduced size)
- Mark perf baselines per architecture to detect regressions

---

## Deep Reference — Full v5
## XPScerpto — Performance

<!-- TOC-BEGIN -->
## Table of Contents

- [Overview](#overview)
- [Performance Design Principles](#performance-design-principles)
- [Hardware Acceleration & ISA Support](#hardware-acceleration--isa-support)
  - [x86‑64 (Intel/AMD)](#x8664-intelamd)
  - [ARMv8 / AArch64](#armv8--aarch64)
  - [RISC‑V](#riscv)
  - [Runtime Dispatch](#runtime-dispatch)
- [Parallelism & Batching](#parallelism--batching)
- [Algorithm‑Specific Notes](#algorithmspecific-notes)
  - [AES‑GCM](#aesgcm)
  - [ChaCha20‑Poly1305](#chacha20poly1305)
  - [SHA‑2 / SHA‑3 / BLAKE2 / BLAKE3](#sha2--sha3--blake2--blake3)
  - [Ed25519 / X25519](#ed25519--x25519)
  - [RSA / Big‑Integer](#rsa--biginteger)
  - [PQC (Kyber, Dilithium, Falcon)](#pqc-kyber-dilithium-falcon)
  - [DRBG (CTR‑DRBG)](#drbg-ctrdrbg)
- [Memory, Cache & I/O Efficiency](#memory-cache--io-efficiency)
- [Auto‑Calibration & Fast Paths](#autocalibration--fast-paths)
- [Benchmark Methodology](#benchmark-methodology)
  - [Built‑In Harnesses (examples)](#builtin-harnesses-examples)
  - [Interpreting Sample Output](#interpreting-sample-output)
- [Tuning Guide](#tuning-guide)
  - [Build & Toolchain](#build--toolchain)
  - [ISA Control](#isa-control)
  - [Parallelism](#parallelism)
  - [Memory & I/O](#memory--io)
  - [Algorithm Choices](#algorithm-choices)
- [Expected Qualitative Performance](#expected-qualitative-performance)
- [Performance Checklist](#performance-checklist)
- [Reproducibility Recipe (Example)](#reproducibility-recipe-example)
- [Appendix: Notes on Constant‑Time & SIMD](#appendix-notes-on-constanttime--simd)
- [Merged from `simd/PERFORMANCE.md`](#merged-from-simdperformancemd)
- [1. KPIs](#1-kpis)
- [2. Tuning Strategy](#2-tuning-strategy)
  - [Representative Sizes](#representative-sizes)
- [3. AVX‑512 Demotion](#3-avx512-demotion)
- [4. Target Expectations (non-binding, indicative)](#4-target-expectations-non-binding-indicative)
- [5. Benchmarking Playbook](#5-benchmarking-playbook)
- [6. SLA Gates (example CI)](#6-sla-gates-example-ci)
- [7. Profiling](#7-profiling)
- [8. Pseudocode of Microbench](#8-pseudocode-of-microbench)
- [Merged from `auto_rotation/PERFORMANCE.md`](#merged-from-autorotationperformancemd)
- [1) Key Paths](#1-key-paths)
- [2) Recommended Settings](#2-recommended-settings)
- [3) Benchmarks (Design)](#3-benchmarks-design)
- [4) Optimization Levers](#4-optimization-levers)
- [5) Observability](#5-observability)
- [Merged from `super/PERFORMANCE.md`](#merged-from-superperformancemd)
- [Key Paths](#key-paths)
- [Tuning](#tuning)
- [Benchmarks](#benchmarks)
- [Observability](#observability)
<!-- TOC-END -->


## Overview

**XPScerpto** is engineered to deliver strong security **without** sacrificing throughput or latency—even under high‑load, low‑latency, or resource‑constrained conditions. This document explains how the library attains high performance across architectures, how to tune it for your environment, and how to measure results reliably.

---

## Performance Design Principles

- **Runtime ISA Dispatch:** Choose the best available implementation at runtime (e.g., AVX2/AVX‑512, ARMv8 CE, RVV) with safe fallbacks.
- **SIMD‑First Kernels:** Hot paths are vectorized where safe, with constant‑time behavior preserved for secret‑dependent code.
- **Parallel & Batched Execution:** Hashing, symmetric modes (CTR/GCM), and signature verification support coarse‑grained parallelism and batch APIs.
- **Cache‑Aware Layouts:** Block sizes, alignment, and prefetching are tuned to reduce cache misses and TLB pressure.
- **Fast Paths & Auto‑Calibration:** Short‑input fast paths and micro‑probes select the best variant per machine at startup.
- **Bounded Allocations:** Prefer stack/arena storage and reuse to reduce allocator overhead and improve locality.
- **Zero‑Overhead Safety:** Error paths and guards are optimized to avoid steady‑state penalties.

> **Note:** Constant‑time rules apply to secret‑handling code; vectorization is used only where it doesn’t create data‑dependent timing or memory access.

---

## Hardware Acceleration & ISA Support

### x86‑64 (Intel/AMD)
- **AES‑NI** for AES rounds, **PCLMULQDQ** for GHASH (GCM), **SHA extensions** (where available).
- **SSE2/SSSE3/SSE4.1/AVX/AVX2/AVX‑512** vector backends for hashes (SHA‑2/3, BLAKE2/3), MACs, and memory primitives.
- **BMI2/ADX** leveraged for big‑integer routines where applicable.

### ARMv8 / AArch64
- **Crypto Extensions (CE)**: AES and SHA acceleration in hardware.
- **NEON** vector paths for symmetric ciphers, hashes, and memory operations.

### RISC‑V
- **RVV (Vector Extension)** backends exist for selected primitives (e.g., sponge/extendable‑output paths), with scalar fallbacks.

### Runtime Dispatch
At initialization, the library queries CPU features and selects the **best compatible** backend (e.g., AVX2 vs. SSE4.1). If dispatch is disabled by policy/build, the **portable scalar** path is used.

---

## Parallelism & Batching

- **Symmetric encryption**: CTR/CTR‑like and GCM can process multiple blocks in parallel; AEAD verify remains constant‑time.
- **Hashing**: Tree or lane‑parallel hashing (e.g., BLAKE3) exploits threads/SIMD for high throughput.
- **Signature verification batching**: Optional batch APIs reduce per‑signature overhead (especially for PQ signatures).
- **Threading model**: Library is **thread‑safe** but does not spawn worker threads by default; use your application’s thread‑pool/async runtime.

---

## Algorithm‑Specific Notes

### AES‑GCM
- AES rounds via AES‑NI (x86) or ARM CE; GHASH via PCLMULQDQ (x86) or NEON multiplications.
- Nonces/IVs are generated distinctly per message; GHASH state is pipelined.

### ChaCha20‑Poly1305
- Vectorized quarter‑rounds and fused Poly1305 accumulation for minimal store/load traffic; competitive on CPUs without AES‑NI.

### SHA‑2 / SHA‑3 / BLAKE2 / BLAKE3
- SHA‑2/3 have AVX2/NEON lanes where safe; SHA‑3’s sponge absorbs in wide chunks.
- BLAKE3 uses tree mode with parallel chunks, scaling well across cores.

### Ed25519 / X25519
- Uses table‑based, constant‑time field ops; batch verify reduces overhead for many signatures.
- Scalar ops avoid secret‑dependent branches; memory access is masked/constant‑time.

### RSA / Big‑Integer
- Karatsuba/Comba hybrids; Montgomery reduction with optional ADX/BMI2 acceleration.
- CRT optimize for private‑key operations; blinding by default.

### PQC (Kyber, Dilithium, Falcon)
- NTT and polynomial kernels vectorized where available; memory reuse reduces footprint.
- Batch verification recommended when throughput matters.

### DRBG (CTR‑DRBG)
- Generates in **blocks**, amortizing AES calls; can leverage AES‑NI/CE when enabled.

---

## Memory, Cache & I/O Efficiency

- **Alignment**: 32/64‑byte alignment for AVX2/AVX‑512 hot buffers.
- **Non‑Temporal Stores**: Enabled above a tunable threshold to avoid cache pollution for bulk copies/streams.
- **Prefetching**: Strategic prefetch and contiguous layouts minimize stalls.
- **Arena/Stack Buffers**: Temporary buffers avoid frequent heap traffic.

> Tunables such as `nontemporal_threshold_*` and buffer alignment are selected per‑ISA; the defaults are sensible for general workloads.

---

## Auto‑Calibration & Fast Paths

On first use (or at library init), quick micro‑probes can select between close contenders (e.g., SHA‑512 AVX2 vs. SHA‑ext) to pick the **faster** kernel on the **actual** CPU. Short‑message **fast paths** reduce fixed overheads for small payloads (e.g., TLS records, API tokens).

---

## Benchmark Methodology

To obtain **reliable** numbers:
1. **Pin frequency** (disable turbo scaling if you need strict reproducibility).
2. **Warm up** caches and JITs (if any) before timing.
3. Measure both **throughput** (MiB/s, Gb/s) and **latency** (µs/op).
4. Report **cycles/byte** (portable across clock variations).
5. Sweep realistic sizes: 0…64B (small), 4–64KiB (mid), ≥1MiB (bulk).
6. Run multiple iterations; report min/mean/p95.
7. Use dedicated cores or set CPU affinity to reduce noise.

### Built‑In Harnesses (examples)

```bash
# Symmetric/Hash benchmark (example target)
./xps_crypto_bench --algo aes-gcm,blake3,sha3-256 --sizes 64,4096,1048576 --iters 1000 --threads 1

# Memory/move benchmark for the utils backend (example)
./xps_memory_pro_bench --sizes 64,4096,1048576 --iters 200 --csv perf.csv
```

> Exact target names/flags may differ in your build; see your project’s `tests/` tools.

### Interpreting Sample Output

Below is an **example** style of output (from a SHA‑384 test run format) and how to read it:

```
==== Summary: 1452 OK, 8 FAIL ========
Test                                   Bytes   Time[ms]   MiB/s   Cycles/B
-----------------------------------  -------   -------   ------   --------
Streaming eq 512                    4,237,359   8400.47     0.48    2168.14
Key reduction 512                      33,397    133.60     0.24    4365.72
Padding @128-byte boundaries            5,841     31.22     0.18    5833.77
```

- **MiB/s**: bulk throughput (higher is better).
- **Cycles/B**: CPU cycles per byte (lower is better).
- Use both to compare across machines/clocks.

> The example above is illustrative; your results will differ by CPU, build flags, and workload.

---

## Tuning Guide

### Build & Toolchain
- **Compilers**: Clang ≥17 / GCC ≥14 recommended.
- **Flags**: Enable LTO for release builds; ensure module PCH and sanitizer settings are consistent across all targets.
- **Sanitizers**: Use ASan/UBSan/TSan for debug; disable when capturing final perf numbers.

### ISA Control
- Allow the library to auto‑detect ISA at runtime. If you must pin targets, ensure the build **enables** the instruction sets (e.g., `-mavx2` or `-march=armv8.2-a+crypto`) and ships a scalar fallback.

### Parallelism
- For large batches, use batch APIs or parallel lanes (e.g., BLAKE3 tree mode).
- Drive concurrency from your application’s thread‑pool; avoid oversubscription.

### Memory & I/O
- Keep inputs **contiguous** and **aligned**; avoid tiny I/O fragments.
- For bulk streaming, enable non‑temporal stores above the recommended threshold.
- Reuse buffers when possible; avoid per‑call allocations.

### Algorithm Choices
- Prefer **AES‑GCM** on CPUs with AES acceleration; **ChaCha20‑Poly1305** on platforms without.
- For hashing: **BLAKE3** for bulk throughput; **SHA‑2/3** where mandated by policy.
- Use **batch verify** for many signatures (including PQ signatures).

---

## Expected Qualitative Performance

- **AES‑GCM (AES‑NI/CE)** can approach memory bandwidth on modern servers.
- **ChaCha20‑Poly1305** competes well on CPUs lacking AES acceleration.
- **BLAKE3** scales with cores; SHA‑3 benefits from wide SIMD lanes.
- **Ed25519/X25519** are low‑latency; batch verify increases throughput.
- **PQC** (Kyber/Dilithium/Falcon) is slower than classical—but batched verification + vectorized NTT narrows the gap.

> Always validate in your own environment; micro‑architectural details (cache, prefetchers, clock policy) matter.

---

## Performance Checklist

- [ ] Build Release with LTO and consistent module/PCH flags.
- [ ] Verify ISA dispatch detects expected features (print banner/logs).
- [ ] Enable batch/parallel paths where applicable.
- [ ] Use aligned, contiguous buffers; reuse temporaries.
- [ ] Set non‑temporal thresholds for bulk streaming.
- [ ] Benchmark with warm‑up and multiple iterations.
- [ ] Track **cycles/byte** and **MiB/s** across sizes.
- [ ] Re‑test after kernel/firmware/compiler updates.

---

## Reproducibility Recipe (Example)

1. **Hardware**: Document CPU model, cores, frequency policy (turbo on/off), RAM, NUMA.
2. **Software**: OS/kernel, compiler versions, link flags (LTO/ThinLTO), sanitizer status.
3. **Build**: Exact CMake cache and flags; ISA toggles; dispatch policy.
4. **Workload**: Algorithms, message sizes, iteration counts, threads.
5. **Results**: Min/mean/p95 latency, throughput, cycles/byte; raw logs attached.

Keeping a reproducibility log helps correlate regressions and verify improvements over time.

---

## Appendix: Notes on Constant‑Time & SIMD

Where secrets are involved (keys, nonces, intermediate state), kernels avoid data‑dependent branches and data‑dependent memory lookups. SIMD is applied only when it preserves constant‑time behavior; otherwise scalar safe code is used. Validation tests include KATs and randomized differential checks across all backends (scalar vs. SIMD) to ensure equivalence.

---

*XPScerpto — High‑performance cryptography without compromising security.*


---

## Merged from `simd/PERFORMANCE.md`

#XPScerpto — Performance Guide
**Version:** v4 • **Generated:** 2025-11-02 11:52 UTC

## 1. KPIs
- **Throughput (MiB/s)**, **Latency (ns/op)**, **Cycles/byte**, **Tail latency (p99)** for short buffers.
- Goal: **near‑optimal** vs hand‑picked ISA per platform with < 1 indirect call overhead on hot path.

## 2. Tuning Strategy
1. Filter by policy & capability.
2. Measure survivors for 3 sizes (small/medium/large).
3. Pick winners per bucket; pick overall; publish atomically.

### Representative Sizes
- **48 B** (header/records), **1536 B** (TLS-ish), **65536 B** (streaming).

## 3. AVX‑512 Demotion
- Default demotion avoids frequency cliffs under mixed workloads.
- Override with `XPS_SIMD_AVX512_DEMOTION=0` on servers dedicated to crypto streams.

## 4. Target Expectations (non-binding, indicative)
| Algo     | ISA             | Size        | Target (single core) |
|----------|-----------------|-------------|----------------------|
| AES‑CTR  | AVX2+AESNI      | ≥ 64 KiB    | 8–20 GiB/s           |
| AES‑GCM  | AVX2+PCLMUL     | ≥ 64 KiB    | 4–10 GiB/s           |
| Poly1305 | AVX2            | ≥ 64 KiB    | 10–20 GiB/s          |
| X25519   | NEON/AVX2       | scalar op   | tens of Mcycles/op   |

(Real numbers depend on micro‑architecture, clock, memory.)

## 5. Benchmarking Playbook
- **CPU isolation:** pin the calibration thread (e.g., `sched_setaffinity`) to reduce jitter.
- **Governor:** set performance or disable deep C‑states for stable runs.
- **Warmup:** 2–3 iterations before timing; use steady_clock or TSC if safe.
- **Data:** use cache‑warm and cache‑cold scenarios if you test streaming.
- **Repeatability:** disable autotune to compare static vs tuned.

## 6. SLA Gates (example CI)
- AES‑GCM AVX2 ≥ 4 GiB/s (64 KiB blocks) in CI host.
- Poly1305 AVX2 ≥ 10 GiB/s (64 KiB blocks).
- X25519 NEON path must be ≥ portable by ≥ 20%.

## 7. Profiling
- Linux `perf stat/record`, `perf c2c` for cache analysis.
- Count retired instructions and cycles/byte; look for front‑end stalls and bad branch BTBs.

## 8. Pseudocode of Microbench
```cpp
template<class Fn>
double bench(Fn f, size_t len, int iters) {
  auto start = now();
  for (int i=0;i<iters;i++) f(len);
  return ns(now()-start) / double(iters);
}
```


---

## Merged from `auto_rotation/PERFORMANCE.md`

# PERFORMANCE — Auto-Rotation
**Version:** 2025-11-01

---

## 1) Key Paths
- **Scheduler**: O(P) per tick where P = tracked plans (shared_mutex read, minimal write).
- **Provider calls**: dominate latency; model as remote/HSM RPCs (p99 tracked).
- **Distributed**: optional lease/heartbeat; keep lightweight (p50 < 5 ms).

## 2) Recommended Settings
- Tick: 15–60s; align with *schedule granularity* (minute-level is typical).
- Batch generate during low traffic windows; stagger by key group to avoid stampedes.
- Grace window: short for JWT/session keys (hours–days), longer for data-at-rest (days–weeks).

## 3) Benchmarks (Design)
- **Plan Scan**: evaluate 1k plans with N providers (shared-mutex contention).
- **Cutover Latency**: p50/p99 of {generate→activate→commit} per backend.
- **Dual-publish Overhead**: percent of decrypt/sign using old vs new during grace.
- **Distributed Lease**: election + steady-state heartbeat cost.

## 4) Optimization Levers
- Reduce lock contention: per-plan sharded mutex, RCU-style reads if needed.
- Precompute next_due() per plan; update only on events or policy change.
- Async provider calls with bounded concurrency and outbox pattern for retries.
- Cache suite descriptors from `crypto_agile` (atomic snapshot).

## 5) Observability
- Metrics: `auto_rotation_plans`, `events_total{type}`, `cutover_seconds`, `grace_seconds`, `provider_errors_total`.
- Tracing: spans for each lifecycle step with `{key, ver, policy, provider}` tags.


---

## Merged from `super/PERFORMANCE.md`

# PERFORMANCE — XPS Super Crypto
**Version:** 2025-11-01

---

## Key Paths
- **Routing**: O(E) where E = eligible engines for an operation (small).
- **Engine Calls**: dominant latency; track p50/p95/p99 per engine&alg.
- **Hot-Patch**: staging/verify off critical path; commit via ZDT dual-run.

## Tuning
- Weights per engine; prefer local SIMD-accelerated paths for small payloads.
- Batch HSM calls; reuse sessions; leverage AEAD chunking for large data.
- ISA detection (`cross_platform`) to select AVX2/NEON/Scalar.

## Benchmarks
- Route decision latency (ns/op) under policy load.
- Engine throughput (MB/s) for AEAD/hash/MAC/signature families.
- Patch commit latency; failed commit rollback time.

## Observability
- Export: `route_decision_ns`, `engine_errors_total{engine,alg}`, `patch_commits_total`, `patch_failures_total`.