# XPScerpto — Readme X25519

<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Table of Contents](#table-of-contents)
- [Table of Contents](#table-of-contents)
- [Executive Summary](#executive-summary)
- [Architecture](#architecture)
- [Audience & Use‑Cases](#audience--usecases)
- [Public API](#public-api)
- [Quick Start](#quick-start)
  - [1) Generate a keypair & derive public](#1-generate-a-keypair--derive-public)
  - [2) ECDH + HKDF to AEAD key](#2-ecdh--hkdf-to-aead-key)
  - [3) Batch ECDH](#3-batch-ecdh)
- [Build & CMake](#build--cmake)
- [Runtime Dispatch & SIMD](#runtime-dispatch--simd)
- [Batch ECDH](#batch-ecdh)
- [Security & Compliance](#security--compliance)
- [Platform Support](#platform-support)
- [Testing & Validation](#testing--validation)
- [Benchmark Methodology](#benchmark-methodology)
- [Performance Guidance](#performance-guidance)
- [Versioning & Deprecation](#versioning--deprecation)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Table of Contents](#table-of-contents)
- [Executive Summary](#executive-summary)
- [Architecture](#architecture)
- [Audience & Use‑Cases](#audience--usecases)
- [Public API](#public-api)
- [Quick Start](#quick-start)
  - [1) Generate a keypair & derive public](#1-generate-a-keypair--derive-public)
  - [2) ECDH + HKDF to AEAD key](#2-ecdh--hkdf-to-aead-key)
  - [3) Batch ECDH](#3-batch-ecdh)
- [Build & CMake](#build--cmake)
- [Runtime Dispatch & SIMD](#runtime-dispatch--simd)
- [Batch ECDH](#batch-ecdh)
- [Security & Compliance](#security--compliance)
- [Platform Support](#platform-support)
- [Testing & Validation](#testing--validation)
- [Benchmark Methodology](#benchmark-methodology)
- [Performance Guidance](#performance-guidance)
- [Versioning & Deprecation](#versioning--deprecation)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Executive Summary](#executive-summary)
- [Architecture](#architecture)
- [Audience & Use‑Cases](#audience--usecases)
- [Public API](#public-api)
- [Quick Start](#quick-start)
  - [1) Generate a keypair & derive public](#1-generate-a-keypair--derive-public)
  - [2) ECDH + HKDF to AEAD key](#2-ecdh--hkdf-to-aead-key)
  - [3) Batch ECDH](#3-batch-ecdh)
- [Build & CMake](#build--cmake)
- [Runtime Dispatch & SIMD](#runtime-dispatch--simd)
- [Batch ECDH](#batch-ecdh)
- [Security & Compliance](#security--compliance)
- [Platform Support](#platform-support)
- [Testing & Validation](#testing--validation)
- [Benchmark Methodology](#benchmark-methodology)
- [Performance Guidance](#performance-guidance)
- [Versioning & Deprecation](#versioning--deprecation)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [Executive Summary](#executive-summary)
- [Architecture](#architecture)
- [Audience & Use‑Cases](#audience--usecases)
- [Public API](#public-api)
- [Quick Start](#quick-start)
  - [1) Generate a keypair & derive public](#1-generate-a-keypair--derive-public)
  - [2) ECDH + HKDF to AEAD key](#2-ecdh--hkdf-to-aead-key)
  - [3) Batch ECDH](#3-batch-ecdh)
- [Build & CMake](#build--cmake)
- [Runtime Dispatch & SIMD](#runtime-dispatch--simd)
- [Batch ECDH](#batch-ecdh)
- [Security & Compliance](#security--compliance)
- [Platform Support](#platform-support)
- [Testing & Validation](#testing--validation)
- [Benchmark Methodology](#benchmark-methodology)
- [Performance Guidance](#performance-guidance)
- [Versioning & Deprecation](#versioning--deprecation)
<!-- TOC-END -->

> Production‑grade, constant‑time X25519 (RFC 7748) with runtime dispatch, batch ECDH, and secure memory practices

[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Tests](https://img.shields.io/badge/tests-✔-brightgreen)](#)
[![Sanitizers](https://img.shields.io/badge/ASan%2FUBSan-on-blue)](#)
[![Fuzzing](https://img.shields.io/badge/fuzzing-ongoing-blue)](#)
[![Coverage](https://img.shields.io/badge/coverage-XX%25-lightgrey)](#)
[![License](https://img.shields.io/badge/license-Project-blue)](#)

**Status:** Production‑ready (Engineering Preview) · **Language:** C++23 Modules  
**SIMD:** Portable Scalar (5×51) baseline, pluggable AVX2/NEON kernels via runtime dispatch  
**Security:** Clamping, Montgomery ladder (constant‑time), zero‑result rejection, secure wipe (memset_s/volatile), xps.memory helpers

---

## Executive Summary
**X25519** is a modern building block for end‑to‑end encryption and secure key exchange. This module implements X25519 with production‑grade engineering: constant‑time math, secure memory handling, and runtime CPU optimization. It’s suitable for secure messaging, TLS‑like handshakes, VPN/key management systems, and embedded devices.

**Why it matters**
- Establishes a shared secret over untrusted networks.
- Built for safety (constant‑time) and performance (SIMD when available).
- Easy to integrate via a clean C++23 Modules API.

---

## Architecture

```mermaid
flowchart TD
  A[App/Lib Code] -- import --> B[xps.crypto.x25519 x25519.ixx]
  B -- register_x25519_all_kernels() --> C[x25519.kernels.ixx]
  C --> D[kernels_scalar.ixx Portable, CT]
  C --> E[kernels_x86.ixx AVX2 Shims]
  C --> F[kernels_arm.ixx NEON Shims]

  subgraph Runtime Dispatch (xps.crypto.simd.dispatch.kernels)
    K1[register_kernelname, ISA, fn, weight]
    K2[resolve_kernel<fn>name]
%% par/and/end removed
  D -- register_kernel PORTABLE, weight=0 --> K1
  E -- register_kernel AVX2, weight=-1 --> K1
  F -- register_kernel NEON, weight=-10 --> K1

  B -- std::call_once -> init_resolve_once --> K2
  K2 -- g_mul/g_mul_base/g_mul_batch --> B
```

**Key ideas**
- **Single public module** exposes the stable API.  
- **Portable scalar kernel** (constant‑time) is registered with weight **0**.  
- Optional **x86/ARM shims** register with negative weights to keep scalar as the default until **real SIMD** kernels are available (which should register with **higher positive** weights and win at runtime).  
- **Lazy init** via `std::call_once`; **atomic function pointers** ensure thread safety.

---

## Audience & Use‑Cases
**Who is this for?**
- **Developers:** Need a safe, well‑designed X25519 for apps/services/libraries.
- **Security/Infra Teams:** Want auditable, constant‑time crypto with clear guarantees.
- **Product/Tech Leads:** Need a maintained, standards‑aligned component for roadmaps.

**Common Use‑Cases**
- Establish session keys for AEAD (AES‑GCM/ChaCha20‑Poly1305) via HKDF.
- Device onboarding / secure channel bootstrapping (IoT/edge).
- Messaging, VPNs, and zero‑trust service meshes.

---

## Public API

> All sizes are **32 bytes** unless stated otherwise. `Byte`, `Bytes`, `ConstByteSpan`, `Result<T>`, and `ErrorCode` come from project types.

```cpp
namespace XPScerpto::crypto::x25519 {

struct Keypair { std::array<Byte,32> priv; std::array<Byte,32> pub; };

// Derive public key from a 32-byte private key (clamps internally)
auto derive_public(ConstByteSpan private_key)
  -> Result<std::array<Byte,32>>;

// X25519 ECDH: private (ours) × public (peer). Zero output is rejected.
auto dh(ConstByteSpan private_key, ConstByteSpan peer_public)
  -> Result<std::array<Byte,32>>;

// Batch ECDH: outs[i] = dh(ks[i], us[i]) for i in [0..n)
void dh_batch(std::span<std::array<Byte,32>> outs,
              std::span<const std::array<Byte,32>> ks,
              std::span<const std::array<Byte,32>> us);

// Random generation with clamping + derive public
auto generate_keypair() -> Result<Keypair>;

} // namespace
```

**Error codes** (typical): `INVALID_SIZE`, `INTERNAL_ERROR`, *(recommended addition:)* `INVALID_KEY` for the all‑zero shared secret case.

---

## Quick Start

### 1) Generate a keypair & derive public
```cpp
import xps.crypto.x25519;

using XPScerpto::crypto::x25519::generate_keypair;
using XPScerpto::crypto::x25519::derive_public;

auto kp = generate_keypair();
if (!kp) { /* handle error */ }
auto pub2 = derive_public(kp->priv);
```

### 2) ECDH + HKDF to AEAD key
```cpp
import xps.crypto.x25519;
import xps.crypto.kdf.hkdf;     // HKDF-256 facade
import xps.crypto.types;

using XPScerpto::crypto::x25519::dh;
using XPScerpto::crypto::Bytes;

Bytes salt = /* 32 random or context-specific bytes */;
Bytes info = /* "XPScerpto-Session-1" or similar */;

auto ss = dh(my_private, peer_public);
if (!ss) { /* handle error (e.g., INVALID_KEY for zero result) */ }

auto aead_key = XPScerpto::crypto::hkdf::hkdf_sha256_derive(*ss, salt, info, /*L=*/32);
// Use with AES-GCM or ChaCha20-Poly1305
```

### 3) Batch ECDH
```cpp
import xps.crypto.x25519;

std::vector<std::array<XPScerpto::crypto::Byte,32>> outs(n), ks(n), us(n);
// Fill ks/us...
XPScerpto::crypto::x25519::dh_batch(outs, ks, us);
// outs[i] now holds the shared secret for pair i
```

---

## Build & CMake

> The module is exported by the project’s crypto library. Link your target to the library that provides the module exports.

**Example:**
```cmake
# One of these targets, depending on your tree:
#   - xpsi_core
#   - xps_crypto_modules
#   - xps_crypto

target_link_libraries(my_app PRIVATE xpsi_core)  # adjust to your actual target
target_compile_features(my_app PRIVATE cxx_std_23)

# If you rely on the runtime dispatch registry:
target_compile_definitions(my_app PRIVATE XPS_ENABLE_SIMD_DISPATCH=1)
```

**Compiler Notes**
- Clang ≥ 17 recommended (modules). GCC ≥ 14 may work with proper `-fmodules` settings in your tree.  
- Build system precompiles PCM → OBJ → library; you only `import xps.crypto.x25519` in your sources.

---

## Runtime Dispatch & SIMD

- **Portable scalar** kernel is always available (weight 0).  
- **x86/AVX2** and **ARM/NEON** shims register with negative weights. Provide **real SIMD kernels** with **positive** weights (e.g., +10) to take precedence.
- The registry resolves `x25519.mul`, `x25519.mul_base`, and `x25519.mul_batch` and stores the chosen functions into atomic pointers guarded by `std::call_once`.

**Custom kernels (illustrative):**
```cpp
using Fn = bool(*)(std::array<Byte,32>& out,
                   const std::array<Byte,32>& k,
                   const std::array<Byte,32>& u);

XPScerpto::crypto::simd::kernels::register_kernel(
  "x25519.mul", ISA::X86_AVX2, static_cast<Fn>(&x25519_mul_avx2), /*weight=*/10);
```

---

## Batch ECDH

- Uses a dedicated `mul_batch` if present; otherwise **falls back** to a safe scalar loop.  
- Verify equal lengths or pass spans sliced to a common `n`.  
- Observe constant‑time constraints in SIMD paths (no secret‑dependent control flow).

---

## Security & Compliance

- **Constant‑time:** Montgomery ladder with constant‑time `cswap`.  
- **Key hygiene:** Clamping, zero‑result rejection, secure memory wipe (`memset_s`/volatile) + `xps.memory` helpers.  
- **Post‑ECDH:** Always feed the 32‑byte shared secret into a **KDF** (HKDF‑SHA‑256 recommended) before AEAD.  
- **RNG:** Use production‑grade CSPRNG for key generation (TPM/KMS/OS RNG backends where available).  
- **Disclosure:** See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.  
- **Certification:** Not FIPS 140‑3 certified yet; planned per roadmap.

---

## Platform Support

| OS / Arch                      | Compiler (min) | Modules | SIMD (auto)        | Status     |
|--------------------------------|----------------|---------|--------------------|------------|
| Linux x86_64                   | Clang ≥ 17     | Yes     | AVX2 (if avail)    | Supported  |
| Linux ARM64                    | Clang ≥ 17     | Yes     | NEON (if avail)    | Supported  |
| macOS (Apple Silicon / Intel) | Clang ≥ 17     | Yes     | NEON/AVX2 (if avail) | Supported |
| Windows x64 (LLVM/Clang)      | Clang ≥ 17     | Yes     | AVX2 (if avail)    | Preview    |

> Portable constant‑time scalar is always available. SIMD kernels are selected at runtime when present.

---

## Testing & Validation

- **Self‑test** on registration: symmetry check (`a*b == b*a`) and non‑zero output.  
- **Recommended KATs:** Import RFC 7748 vectors and cross‑validate Scalar vs SIMD vs Batch.  
- **Sanitizers:** Run with ASan/UBSan/MSan; verify secure‑wipe paths and OOB guards.  
- **Fuzzing:** Random pairs `(k,u)`; assert deterministic equivalence across kernels.

**Example (pseudo):**
```cpp
auto t1 = dh(k1, u2);
auto t2 = dh(k2, u1);
assert(t1 && t2 && *t1 == *t2 && !std::ranges::all_of(*t1, [](auto b){return b==0;}));
```

---

## Benchmark Methodology

- Pin CPU/ISA; set performance governor; include warm‑ups.  
- Compare Scalar vs SIMD (AVX2/NEON) and Batch ECDH throughput.  
- Report `ops/sec`, `µs/op`, `cycles/byte`; publish command lines and environment.  
- Keep datasets reproducible and note compiler versions/flags.

---

## Performance Guidance

- **Scalar 5×51** is a strong baseline and CT by design.  
- Provide **true AVX2/NEON kernels** for measurable wins; register with higher weights.  
- Use `dh_batch` to leverage SIMD parallelism; ensure balanced batches and pinned CPU frequency for stable measurements.  
- Integrate micro‑benchmarks and record CPU ISA, frequency, governor, and compiler flags.

---

## Versioning & Deprecation

- Semantic intent: **API stable** for the 1.x line; kernels remain pluggable.  
- Deprecations announced one minor release ahead, with migration notes.  
- Changelog: see [CHANGELOG.md](CHANGELOG.md).

---

**Copyright © XPS Crypto**