# Usage Guide

<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Table of Contents](#table-of-contents)
- [1. Build & Install](#1-build--install)
  - [Configure](#configure)
  - [With sanitizers (dev only)](#with-sanitizers-dev-only)
- [2. Consuming the Library](#2-consuming-the-library)
  - [CMake](#cmake)
  - [Compilers](#compilers)
- [3. Recipes](#3-recipes)
  - [3.1 SHA‑384 hash](#31-sha384-hash)
  - [3.2 HKDF‑SHA384 derive key](#32-hkdfsha384-derive-key)
  - [3.3 AES‑GCM seal/open](#33-aesgcm-sealopen)
  - [3.4 Ed25519 sign/verify](#34-ed25519-signverify)
  - [3.5 Falcon‑1024 sign/verify (façade)](#35-falcon1024-signverify-faade)
- [4. Runtime Dispatch & Policies](#4-runtime-dispatch--policies)
- [5. Errors & `expected`](#5-errors--expected)
- [6. Platform Notes](#6-platform-notes)
- [Deep Reference — Full v5](#deep-reference--full-v5)
- [XPScerpto — Usage Guide](#xpscerpto--usage-guide)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [1) Requirements & Build Integration](#1-requirements--build-integration)
  - [CMake (as a subproject)](#cmake-as-a-subproject)
  - [Using the module facade](#using-the-module-facade)
- [2) Quick Start](#2-quick-start)
- [3) AEAD with AAD (AES‑GCM / ChaCha20‑Poly1305)](#3-aead-with-aad-aesgcm--chacha20poly1305)
  - [High-level (facade)](#high-level-facade)
  - [Low-level (explicit cipher object) — optional](#low-level-explicit-cipher-object--optional)
- [4) Ed25519 Sign/Verify](#4-ed25519-signverify)
- [5) X25519 ECDH + HKDF → AEAD Session](#5-x25519-ecdh--hkdf--aead-session)
- [6) Streaming Hash (SHA‑384)](#6-streaming-hash-sha384)
- [7) Key Management with Keyring (Rotation & Revocation)](#7-key-management-with-keyring-rotation--revocation)
- [8) Secure Memory (Locked / Secure Buffers)](#8-secure-memory-locked--secure-buffers)
- [9) Hybrid HPKE (Classical + PQC)](#9-hybrid-hpke-classical--pqc)
- [10) Error Handling (`std::expected` style)](#10-error-handling-stdexpected-style)
- [11) Policies, Orchestration & Hot‑Patch](#11-policies-orchestration--hotpatch)
- [12) Minimal Sanity Tests (you can copy into your app)](#12-minimal-sanity-tests-you-can-copy-into-your-app)
- [13) CMake + Compiler Flags (reference)](#13-cmake--compiler-flags-reference)
- [14) Security Checklist](#14-security-checklist)
- [15) Troubleshooting](#15-troubleshooting)
- [Merged from `simd/USAGE_GUIDE.md`](#merged-from-simdusageguidemd)
- [0. Toolchain Requirements](#0-toolchain-requirements)
- [1. CMake Integration (Modules)](#1-cmake-integration-modules)
- [2. Environment Controls](#2-environment-controls)
- [3. Policy API (Optional)](#3-policy-api-optional)
- [4. AES‑GCM Example](#4-aesgcm-example)
- [5. X25519 Example (ECDH)](#5-x25519-example-ecdh)
- [6. Poly1305 Example (MAC)](#6-poly1305-example-mac)
- [7. Diagnostics & Tracing (Dev Only)](#7-diagnostics--tracing-dev-only)
- [8. Troubleshooting](#8-troubleshooting)
- [9. Minimal Indirection (Manual Resolve)](#9-minimal-indirection-manual-resolve)
- [Merged from `auto_rotation/USAGE_GUIDE.md`](#merged-from-autorotationusageguidemd)
- [1) Quick Start](#1-quick-start)
- [2) Common Operations](#2-common-operations)
- [3) Policies](#3-policies)
- [4) Zero-Downtime (ZDT)](#4-zero-downtime-zdt)
- [5) Compliance Gating](#5-compliance-gating)
- [6) Distributed Mode (Optional)](#6-distributed-mode-optional)
- [7) Troubleshooting](#7-troubleshooting)
- [Merged from `super/USAGE_GUIDE.md`](#merged-from-superusageguidemd)
- [1) Import & Facade](#1-import--facade)
- [2) Route Policy Configuration](#2-route-policy-configuration)
- [3) Operations (Illustrative)](#3-operations-illustrative)
- [4) Hot-Patch Adapter](#4-hot-patch-adapter)
- [5) Rotation Adapter](#5-rotation-adapter)
- [6) XPScerpto Bridge Provider](#6-xpscerpto-bridge-provider)
- [7) Observability](#7-observability)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [1. Build & Install](#1-build--install)
  - [Configure](#configure)
  - [With sanitizers (dev only)](#with-sanitizers-dev-only)
- [2. Consuming the Library](#2-consuming-the-library)
  - [CMake](#cmake)
  - [Compilers](#compilers)
- [3. Recipes](#3-recipes)
  - [3.1 SHA‑384 hash](#31-sha384-hash)
  - [3.2 HKDF‑SHA384 derive key](#32-hkdfsha384-derive-key)
  - [3.3 AES‑GCM seal/open](#33-aesgcm-sealopen)
  - [3.4 Ed25519 sign/verify](#34-ed25519-signverify)
  - [3.5 Falcon‑1024 sign/verify (façade)](#35-falcon1024-signverify-faade)
- [4. Runtime Dispatch & Policies](#4-runtime-dispatch--policies)
- [5. Errors & `expected`](#5-errors--expected)
- [6. Platform Notes](#6-platform-notes)
- [Deep Reference — Full v5](#deep-reference--full-v5)
- [XPScerpto — Usage Guide](#xpscerpto--usage-guide)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [1) Requirements & Build Integration](#1-requirements--build-integration)
  - [CMake (as a subproject)](#cmake-as-a-subproject)
  - [Using the module facade](#using-the-module-facade)
- [2) Quick Start](#2-quick-start)
- [3) AEAD with AAD (AES‑GCM / ChaCha20‑Poly1305)](#3-aead-with-aad-aesgcm--chacha20poly1305)
  - [High-level (facade)](#high-level-facade)
  - [Low-level (explicit cipher object) — optional](#low-level-explicit-cipher-object--optional)
- [4) Ed25519 Sign/Verify](#4-ed25519-signverify)
- [5) X25519 ECDH + HKDF → AEAD Session](#5-x25519-ecdh--hkdf--aead-session)
- [6) Streaming Hash (SHA‑384)](#6-streaming-hash-sha384)
- [7) Key Management with Keyring (Rotation & Revocation)](#7-key-management-with-keyring-rotation--revocation)
- [8) Secure Memory (Locked / Secure Buffers)](#8-secure-memory-locked--secure-buffers)
- [9) Hybrid HPKE (Classical + PQC)](#9-hybrid-hpke-classical--pqc)
- [10) Error Handling (`std::expected` style)](#10-error-handling-stdexpected-style)
- [11) Policies, Orchestration & Hot‑Patch](#11-policies-orchestration--hotpatch)
- [12) Minimal Sanity Tests (you can copy into your app)](#12-minimal-sanity-tests-you-can-copy-into-your-app)
- [13) CMake + Compiler Flags (reference)](#13-cmake--compiler-flags-reference)
- [14) Security Checklist](#14-security-checklist)
- [15) Troubleshooting](#15-troubleshooting)
- [Merged from `simd/USAGE_GUIDE.md`](#merged-from-simdusageguidemd)
- [0. Toolchain Requirements](#0-toolchain-requirements)
- [1. CMake Integration (Modules)](#1-cmake-integration-modules)
- [2. Environment Controls](#2-environment-controls)
- [3. Policy API (Optional)](#3-policy-api-optional)
- [4. AES‑GCM Example](#4-aesgcm-example)
- [5. X25519 Example (ECDH)](#5-x25519-example-ecdh)
- [6. Poly1305 Example (MAC)](#6-poly1305-example-mac)
- [7. Diagnostics & Tracing (Dev Only)](#7-diagnostics--tracing-dev-only)
- [8. Troubleshooting](#8-troubleshooting)
- [9. Minimal Indirection (Manual Resolve)](#9-minimal-indirection-manual-resolve)
- [Merged from `auto_rotation/USAGE_GUIDE.md`](#merged-from-autorotationusageguidemd)
- [1) Quick Start](#1-quick-start)
- [2) Common Operations](#2-common-operations)
- [3) Policies](#3-policies)
- [4) Zero-Downtime (ZDT)](#4-zero-downtime-zdt)
- [5) Compliance Gating](#5-compliance-gating)
- [6) Distributed Mode (Optional)](#6-distributed-mode-optional)
- [7) Troubleshooting](#7-troubleshooting)
- [Merged from `super/USAGE_GUIDE.md`](#merged-from-superusageguidemd)
- [1) Import & Facade](#1-import--facade)
- [2) Route Policy Configuration](#2-route-policy-configuration)
- [3) Operations (Illustrative)](#3-operations-illustrative)
- [4) Hot-Patch Adapter](#4-hot-patch-adapter)
- [5) Rotation Adapter](#5-rotation-adapter)
- [6) XPScerpto Bridge Provider](#6-xpscerpto-bridge-provider)
- [7) Observability](#7-observability)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [1. Build & Install](#1-build--install)
  - [Configure](#configure)
  - [With sanitizers (dev only)](#with-sanitizers-dev-only)
- [2. Consuming the Library](#2-consuming-the-library)
  - [CMake](#cmake)
  - [Compilers](#compilers)
- [3. Recipes](#3-recipes)
  - [3.1 SHA‑384 hash](#31-sha384-hash)
  - [3.2 HKDF‑SHA384 derive key](#32-hkdfsha384-derive-key)
  - [3.3 AES‑GCM seal/open](#33-aesgcm-sealopen)
  - [3.4 Ed25519 sign/verify](#34-ed25519-signverify)
  - [3.5 Falcon‑1024 sign/verify (façade)](#35-falcon1024-signverify-faade)
- [4. Runtime Dispatch & Policies](#4-runtime-dispatch--policies)
- [5. Errors & `expected`](#5-errors--expected)
- [6. Platform Notes](#6-platform-notes)
- [Deep Reference — Full v5](#deep-reference--full-v5)
- [XPScerpto — Usage Guide](#xpscerpto--usage-guide)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [1) Requirements & Build Integration](#1-requirements--build-integration)
  - [CMake (as a subproject)](#cmake-as-a-subproject)
  - [Using the module facade](#using-the-module-facade)
- [2) Quick Start](#2-quick-start)
- [3) AEAD with AAD (AES‑GCM / ChaCha20‑Poly1305)](#3-aead-with-aad-aesgcm--chacha20poly1305)
  - [High-level (facade)](#high-level-facade)
  - [Low-level (explicit cipher object) — optional](#low-level-explicit-cipher-object--optional)
- [4) Ed25519 Sign/Verify](#4-ed25519-signverify)
- [5) X25519 ECDH + HKDF → AEAD Session](#5-x25519-ecdh--hkdf--aead-session)
- [6) Streaming Hash (SHA‑384)](#6-streaming-hash-sha384)
- [7) Key Management with Keyring (Rotation & Revocation)](#7-key-management-with-keyring-rotation--revocation)
- [8) Secure Memory (Locked / Secure Buffers)](#8-secure-memory-locked--secure-buffers)
- [9) Hybrid HPKE (Classical + PQC)](#9-hybrid-hpke-classical--pqc)
- [10) Error Handling (`std::expected` style)](#10-error-handling-stdexpected-style)
- [11) Policies, Orchestration & Hot‑Patch](#11-policies-orchestration--hotpatch)
- [12) Minimal Sanity Tests (you can copy into your app)](#12-minimal-sanity-tests-you-can-copy-into-your-app)
- [13) CMake + Compiler Flags (reference)](#13-cmake--compiler-flags-reference)
- [14) Security Checklist](#14-security-checklist)
- [15) Troubleshooting](#15-troubleshooting)
- [Merged from `simd/USAGE_GUIDE.md`](#merged-from-simdusageguidemd)
- [0. Toolchain Requirements](#0-toolchain-requirements)
- [1. CMake Integration (Modules)](#1-cmake-integration-modules)
- [2. Environment Controls](#2-environment-controls)
- [3. Policy API (Optional)](#3-policy-api-optional)
- [4. AES‑GCM Example](#4-aesgcm-example)
- [5. X25519 Example (ECDH)](#5-x25519-example-ecdh)
- [6. Poly1305 Example (MAC)](#6-poly1305-example-mac)
- [7. Diagnostics & Tracing (Dev Only)](#7-diagnostics--tracing-dev-only)
- [8. Troubleshooting](#8-troubleshooting)
- [9. Minimal Indirection (Manual Resolve)](#9-minimal-indirection-manual-resolve)
- [Merged from `auto_rotation/USAGE_GUIDE.md`](#merged-from-autorotationusageguidemd)
- [1) Quick Start](#1-quick-start)
- [2) Common Operations](#2-common-operations)
- [3) Policies](#3-policies)
- [4) Zero-Downtime (ZDT)](#4-zero-downtime-zdt)
- [5) Compliance Gating](#5-compliance-gating)
- [6) Distributed Mode (Optional)](#6-distributed-mode-optional)
- [7) Troubleshooting](#7-troubleshooting)
- [Merged from `super/USAGE_GUIDE.md`](#merged-from-superusageguidemd)
- [1) Import & Facade](#1-import--facade)
- [2) Route Policy Configuration](#2-route-policy-configuration)
- [3) Operations (Illustrative)](#3-operations-illustrative)
- [4) Hot-Patch Adapter](#4-hot-patch-adapter)
- [5) Rotation Adapter](#5-rotation-adapter)
- [6) XPScerpto Bridge Provider](#6-xpscerpto-bridge-provider)
- [7) Observability](#7-observability)
<!-- TOC-END -->


This guide shows how to **build**, **link**, and **use** XPScerpto. It also covers platform flags, sanitizers, and typical code recipes.

## 1. Build & Install

### Configure
```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_ASAN=OFF -DENABLE_UBSAN=OFF
cmake --build build -j
cmake --install build --prefix /usr/local
```

### With sanitizers (dev only)
```bash
cmake -S . -B build-s -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_ASAN=ON -DENABLE_UBSAN=ON
cmake --build build-s -j
ctest --test-dir build-s --output-on-failure
```

## 2. Consuming the Library

### CMake
```cmake
find_package(XPScerpto CONFIG REQUIRED)
add_executable(app main.cpp)
target_link_libraries(app PRIVATE xps.crypto) # or granular modules
```

### Compilers
- **Clang 19+**: preferred for modules and sanitizers
- **GCC 14+**: supported with module scanning fallback
- **MSVC**: limited module support; rely on static façade targets if needed

## 3. Recipes

### 3.1 SHA‑384 hash
```cpp
import xps.crypto.hash.sha384;
auto d = xps::crypto::hash::sha384::digest("abc", 3);
```

### 3.2 HKDF‑SHA384 derive key
```cpp
import xps.crypto.kdf.hkdf;
import xps.crypto.hash.sha384;
unsigned char prk[48], out[32];
xps::crypto::kdf::hkdf::extract(xps::crypto::hash::sha384::hmac, nullptr, 0,
                                (const unsigned char*)"ikm", 3, prk, sizeof(prk));
xps::crypto::kdf::hkdf::expand(xps::crypto::hash::sha384::hmac, prk, sizeof(prk),
                               (const unsigned char*)"ctx", 3, out, sizeof(out));
```

### 3.3 AES‑GCM seal/open
```cpp
import xps.crypto.aead.aes_gcm;
unsigned char key[32]{}, iv[12]{}, tag[16]{}, pt[32]{}, ct[32]{};
xps::crypto::aead::aes_gcm::seal(key, 32, iv, 12, nullptr, 0, pt, 32, ct, tag);
bool ok = xps::crypto::aead::aes_gcm::open(key, 32, iv, 12, nullptr, 0, ct, 32, pt, tag);
```

### 3.4 Ed25519 sign/verify
```cpp
import xps.crypto.sign.ed25519;
auto kp = xps::crypto::ed25519::keypair::generate();
unsigned char sig[64];
xps::crypto::ed25519::sign(kp.sk, kp.pk, (const unsigned char*)"m", 1, sig);
bool good = xps::crypto::ed25519::verify(kp.pk, (const unsigned char*)"m", 1, sig);
```

### 3.5 Falcon‑1024 sign/verify (façade)
```cpp
import xps.crypto.falcon1024; // stable façade
using namespace xps::crypto::falcon1024;
auto sk = secret_key::generate();
auto pk = public_key::from_secret(sk);
auto sig = sign(pk, sk, std::as_bytes(std::span{"data"}));
bool good = verify(pk, std::as_bytes(std::span{"data"}), sig);
```

## 4. Runtime Dispatch & Policies

- Env vars or config can **disable** certain ISAs (e.g., `XPS_DISABLE_AVX2=1`).
- Constant‑time policy can be forced globally.
- Nontemporal thresholds for large buffers can be tuned.

## 5. Errors & `expected`

```cpp
import xps.expected;
auto r = xps::crypto::aead::aes_gcm::try_open(...);
if (!r) {
  // r.error() is a strong ErrorCode mapped in ERROR_TAXONOMY.md
}
```

## 6. Platform Notes

- **Linux**: `explicit_bzero` used if available.
- **macOS**: target recent SDK; AVX‑512 not on common mobiles.
- **Windows**: enable `/EHsc` only where needed; prefer static runtime for tools.

---

## Deep Reference — Full v5
## XPScerpto — Usage Guide

<!-- TOC-BEGIN -->
## Table of Contents

- [Overview](#overview)
- [1) Requirements & Build Integration](#1-requirements--build-integration)
  - [CMake (as a subproject)](#cmake-as-a-subproject)
  - [Using the module facade](#using-the-module-facade)
- [2) Quick Start](#2-quick-start)
- [3) AEAD with AAD (AES‑GCM / ChaCha20‑Poly1305)](#3-aead-with-aad-aesgcm--chacha20poly1305)
  - [High-level (facade)](#high-level-facade)
  - [Low-level (explicit cipher object) — optional](#low-level-explicit-cipher-object--optional)
- [4) Ed25519 Sign/Verify](#4-ed25519-signverify)
- [5) X25519 ECDH + HKDF → AEAD Session](#5-x25519-ecdh--hkdf--aead-session)
- [6) Streaming Hash (SHA‑384)](#6-streaming-hash-sha384)
- [7) Key Management with Keyring (Rotation & Revocation)](#7-key-management-with-keyring-rotation--revocation)
- [8) Secure Memory (Locked / Secure Buffers)](#8-secure-memory-locked--secure-buffers)
- [9) Hybrid HPKE (Classical + PQC)](#9-hybrid-hpke-classical--pqc)
- [10) Error Handling (`std::expected` style)](#10-error-handling-stdexpected-style)
- [11) Policies, Orchestration & Hot‑Patch](#11-policies-orchestration--hotpatch)
- [12) Minimal Sanity Tests (you can copy into your app)](#12-minimal-sanity-tests-you-can-copy-into-your-app)
- [13) CMake + Compiler Flags (reference)](#13-cmake--compiler-flags-reference)
- [14) Security Checklist](#14-security-checklist)
- [15) Troubleshooting](#15-troubleshooting)
- [Merged from `simd/USAGE_GUIDE.md`](#merged-from-simdusageguidemd)
- [0. Toolchain Requirements](#0-toolchain-requirements)
- [1. CMake Integration (Modules)](#1-cmake-integration-modules)
- [2. Environment Controls](#2-environment-controls)
- [3. Policy API (Optional)](#3-policy-api-optional)
- [4. AES‑GCM Example](#4-aesgcm-example)
- [5. X25519 Example (ECDH)](#5-x25519-example-ecdh)
- [6. Poly1305 Example (MAC)](#6-poly1305-example-mac)
- [7. Diagnostics & Tracing (Dev Only)](#7-diagnostics--tracing-dev-only)
- [8. Troubleshooting](#8-troubleshooting)
- [9. Minimal Indirection (Manual Resolve)](#9-minimal-indirection-manual-resolve)
- [Merged from `auto_rotation/USAGE_GUIDE.md`](#merged-from-autorotationusageguidemd)
- [1) Quick Start](#1-quick-start)
- [2) Common Operations](#2-common-operations)
- [3) Policies](#3-policies)
- [4) Zero-Downtime (ZDT)](#4-zero-downtime-zdt)
- [5) Compliance Gating](#5-compliance-gating)
- [6) Distributed Mode (Optional)](#6-distributed-mode-optional)
- [7) Troubleshooting](#7-troubleshooting)
- [Merged from `super/USAGE_GUIDE.md`](#merged-from-superusageguidemd)
- [1) Import & Facade](#1-import--facade)
- [2) Route Policy Configuration](#2-route-policy-configuration)
- [3) Operations (Illustrative)](#3-operations-illustrative)
- [4) Hot-Patch Adapter](#4-hot-patch-adapter)
- [5) Rotation Adapter](#5-rotation-adapter)
- [6) XPScerpto Bridge Provider](#6-xpsi-bridge-provider)
- [7) Observability](#7-observability)
<!-- TOC-END -->


## Overview

This guide shows how to use **XPScerpto Crypto** in real-world applications. It focuses on a clean, safe, and *production‑grade* developer experience using modern C++ Modules (C++23). You’ll find end‑to‑end recipes for:
- AEAD encryption with **AAD** (AES‑GCM & ChaCha20‑Poly1305)
- Public‑key signatures with **Ed25519**
- Key agreement with **X25519** + HKDF → AES‑GCM session keys
- Streaming **SHA‑384** hashing API
- Key management with **Keyring** (rotation, revocation, password‑protected export)
- **Hybrid HPKE** (classical + post‑quantum) sealing/opening
- Error handling with `std::expected`-style results
- Secure memory with **Locked/Secure buffers**
- Policy controls, orchestration, and hot‑patch/zero‑downtime notes
- Minimal CMake integration

> **Note**  
> Module names below reflect the canonical structure used across XPS Crypto. If your local tree exposes a single **facade** (e.g., `import xps.crypto.api;`), you can stick to the facade for most tasks, or import specialized modules when you need lower‑level control.

---

## 1) Requirements & Build Integration

- **Compiler:** Clang ≥ 17 or GCC ≥ 14 with C++23 modules enabled.
- **OS:** Linux/macOS/Windows; x86‑64/ARM64 (SIMD paths selected at runtime).
- **CMake:** `cmake_minimum_required(VERSION 3.31)` recommended.

### CMake (as a subproject)

```cmake
# Top-level CMakeLists.txt (excerpt)
add_subdirectory(external/xpsi-crypto)

# If the project provides an interface target:
target_link_libraries(my_app PRIVATE xps_crypto)

# Use C++23 and modules
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
```

### Using the module facade

```cpp
import xps.crypto.api;  // single import for the common API
// Optionally: import specialized modules when needed, e.g.:
import xps.crypto.hash.sha384;
import xps.crypto.kdf.hkdf;
import xps.crypto.base64x;
import xps.memory; // secure buffers
```

---

## 2) Quick Start

```cpp
import xps.crypto.api;
import xps.crypto.base64x;
import xps.memory;

using XPScerpto::crypto::Bytes;

// Random bytes (CS-PRNG)
Bytes iv = XPScerpto::crypto::random_bytes(12);

// Hex/Base64 helpers
std::string b64 = XPScerpto::crypto::base64x::encode(iv);
Bytes back = XPScerpto::crypto::base64x::decode(b64);
```

> **Secure defaults.** If you call the high-level AEAD helpers without an algorithm hint, the policy engine will select a strong default (e.g., AES‑256‑GCM or ChaCha20‑Poly1305).

---

## 3) AEAD with AAD (AES‑GCM / ChaCha20‑Poly1305)

### High-level (facade)

```cpp
import xps.crypto.api;

using XPScerpto::crypto::Bytes;

// 1) Key & nonce
Bytes key   = XPScerpto::crypto::random_bytes(32); // AES‑256 / ChaCha20 key
Bytes nonce = XPScerpto::crypto::random_bytes(12); // 96-bit recommended

// 2) Plaintext & AAD (not encrypted, but authenticated)
Bytes pt   = Bytes{'H','e','l','l','o'};
Bytes aad  = Bytes{'m','e','t','a'};

// 3) Encrypt (AEAD)
auto enc = XPScerpto::crypto::aead::encrypt({
    .algo  = XPScerpto::crypto::AEAD::AES_GCM, // or AEAD::CHACHA20_POLY1305
    .key   = key,
    .nonce = nonce,
    .aad   = aad,
    .plain = pt,
});
if (!enc) { /* handle enc.error() */ }

// enc->cipher includes tag (implementation-defined layout)
auto dec = XPScerpto::crypto::aead::decrypt({
    .algo   = XPScerpto::crypto::AEAD::AES_GCM,
    .key    = key,
    .nonce  = nonce,
    .aad    = aad,
    .cipher = enc->cipher,
});
if (!dec) { /* handle dec.error() */ }

// dec->plain == pt
```

### Low-level (explicit cipher object) — optional

```cpp
import xps.crypto.aead.aes_gcm; // when enabled in your build

XPScerpto::crypto::aead::AESGCM cipher;
cipher.set_key(key);
cipher.set_nonce(nonce);
cipher.set_aad(aad);

auto c = cipher.encrypt(pt);      // returns {ciphertext, tag}
auto p = cipher.decrypt(c);       // verifies tag, returns plaintext
```

> **Nonce/IV discipline:** Never reuse a (key, nonce) pair. Use a counter or random nonces with collision tracking. The facade can auto‑generate nonces if omitted, and will return them alongside the ciphertext bundle.

---

## 4) Ed25519 Sign/Verify

```cpp
import xps.crypto.ed25519.api;

auto [pub, priv] = XPScerpto::crypto::ed25519::generate_keypair();

std::vector<std::byte> msg{/*...*/};

auto sig = XPScerpto::crypto::ed25519::sign(msg, priv);
bool ok  = XPScerpto::crypto::ed25519::verify(msg, sig, pub);
```

> Store private keys encrypted at rest; wipe them from RAM as soon as you can (see §8 Secure Memory).

---

## 5) X25519 ECDH + HKDF → AEAD Session

```cpp
import xps.crypto.x25519.api;
import xps.crypto.kdf.hkdf;
import xps.crypto.aead.aes_gcm;

// Alice
auto [A_pub, A_priv] = XPScerpto::crypto::x25519::generate_keypair();
// Bob
auto [B_pub, B_priv] = XPScerpto::crypto::x25519::generate_keypair();

// Derive shared secret on each side
auto sA = XPScerpto::crypto::x25519::derive_shared(A_priv, B_pub); // 32 bytes
auto sB = XPScerpto::crypto::x25519::derive_shared(B_priv, A_pub); // == sA

// Strengthen with HKDF-SHA256 to 32-byte session key
auto session = XPScerpto::crypto::hkdf::derive({
  .ikm = sA,
  .salt = std::nullopt,
  .info = std::vector<std::byte>{},
  .length = 32
});

// Use as AEAD key (AES‑256‑GCM for example)
Bytes nonce = XPScerpto::crypto::random_bytes(12);
auto enc = XPScerpto::crypto::aead::encrypt({
  .algo = XPScerpto::crypto::AEAD::AES_GCM,
  .key = session,
  .nonce = nonce,
  .plain = Bytes{'s','e','c','r','e','t'}
});
```

---

## 6) Streaming Hash (SHA‑384)

```cpp
import xps.crypto.hash.sha384;
import xps.crypto.hex;

XPScerpto::crypto::sha384::StreamingHasher H;
H.update(std::as_bytes(std::span{"Hello "sv}));
H.update(std::as_bytes(std::span{"World"sv}));
auto digest = H.final(); // 48 bytes

std::string hex = XPScerpto::crypto::hex::encode(digest);
```

> The SHA‑384 module exposes one‑shot and streaming APIs. The streaming API minimizes copies and is ideal for large files, sockets, and mmap‑backed inputs.

---

## 7) Key Management with Keyring (Rotation & Revocation)

```cpp
import xps.crypto.keyring;
import xps.memory;

// Create an in‑process keyring
XPScerpto::crypto::keyring::Keyring kr;

// Generate & register a named key
auto k = XPScerpto::crypto::random_bytes(32);
auto id = kr.add("payments/aead", k);

// Policy: rotate this key every 90 days or 2^32 ops (whichever first)
kr.policy("payments/aead").rotate_days(90).max_uses(1ull<<32);

// Export to disk (password protected) for backup
xps::memory::LockedBuffer pwd = xps::memory::make_locked("correct-horse-battery-staple");
kr.export_encrypted("kr.backup", pwd);

// Re‑import elsewhere when bootstrapping a node
auto kr2 = XPScerpto::crypto::keyring::Keyring::import_encrypted("kr.backup", pwd);

// Revocation (immediate deny on use)
kr.revoke(id);
```

> The keyring integrates with the **orchestrator/guard** layer to gate sensitive operations, log rotations, and enforce policy‑driven algorithm allowlists/denylists.

---

## 8) Secure Memory (Locked / Secure Buffers)

```cpp
import xps.memory;

using xps::memory::LockedBuffer;

// Allocate page‑locked, non‑swappable memory for secrets
LockedBuffer secret = xps::memory::make_locked(32);
secret.write([](std::span<std::byte> w){
  auto rnd = XPScerpto::crypto::random_bytes(32);
  std::memcpy(w.data(), rnd.data(), w.size());
});

// Zeroize on scope end; explicit wipe if needed
xps::memory::secure_wipe(secret);
```

> Locked buffers attempt to mlock/VirtualLock when available, fall back safely, and always **zeroize** on destruction.

---

## 9) Hybrid HPKE (Classical + PQC)

```cpp
import xps.crypto.hybrid.hpke;

// Recipient publishes (RSA‑3072, Kyber‑1024) public keys
HybridRecipientPubKey R{ .rsa = rsa_pub, .kyber = kyber_pub };

// Sender seals a symmetric CEK twice (classical + PQC) and bundles both
auto sealed = XPScerpto::crypto::hybrid::hpke::seal({
    .recipient = R,
    .aad       = std::vector<std::byte>{},
    .plain     = cek_bytes // content‑encryption key
});

// Recipient opens if *both* sub‑schemes validate (policy dependent)
auto opened = XPScerpto::crypto::hybrid::hpke::open({
    .recipient_priv = { .rsa = rsa_priv, .kyber = kyber_priv },
    .bundle         = sealed->bundle
});
```

> Hybrid HPKE mitigates **“harvest‑now, decrypt‑later”** threats by requiring an attacker to break *both* classical and PQC encapsulations.

---

## 10) Error Handling (`std::expected` style)

All high‑level calls return an `expected<T, Error>` (facade) or throw on error (configurable).

```cpp
auto out = XPScerpto::crypto::aead::encrypt(args);
if (!out) {
  auto e = out.error();
  // switch(e.code) { case Error::PolicyDenied: ... }
}
```

> In performance‑critical code, prefer `expected` and branchless checks over exceptions.

---

## 11) Policies, Orchestration & Hot‑Patch

```cpp
import xps.crypto.policy;
import xps.crypto.orchestrator;

XPScerpto::crypto::policy::set_minimum_key_size({ .rsa_bits = 3072, .aes_bits = 256 });
XPScerpto::crypto::policy::deny_algorithms({ "SHA1", "DES", "RC4" });

// At startup: self‑tests & runtime dispatch (SIMD/ISA detection)
XPScerpto::crypto::orchestrator::self_test_all();

// Hot‑patch a vulnerable module with zero downtime
XPScerpto::crypto::orchestrator::hot_patch("xps.crypto.hash.sha384", "sha384_2025-11-02.signed");
```

> The orchestrator verifies publisher signatures, runs A/B correctness probes, and only flips traffic when the new unit passes gates (**zero_downtime**).

---

## 12) Minimal Sanity Tests (you can copy into your app)

```cpp
// AEAD roundtrip
{
  auto key = XPScerpto::crypto::random_bytes(32);
  auto n   = XPScerpto::crypto::random_bytes(12);
  auto e = XPScerpto::crypto::aead::encrypt({ .key=key, .nonce=n, .plain=Bytes{1,2,3} });
  auto d = XPScerpto::crypto::aead::decrypt({ .key=key, .nonce=n, .cipher=e->cipher });
  assert(d && d->plain == Bytes{1,2,3});
}
```

---

## 13) CMake + Compiler Flags (reference)

- Enable LTO in Release, sanitizers in Debug.
- Avoid forcing global `-mavx2`; use runtime dispatch.

```cmake
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_ok)
  if(ipo_ok) set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON) endif()
endif()

# Example: toggle sanitizers in Debug
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-fsanitize=address,undefined)
  add_link_options(-fsanitize=address,undefined)
endif()
```

---

## 14) Security Checklist

- Never reuse AEAD nonce with the same key.
- Zeroize secrets (RAM) and encrypt private keys at rest.
- Enforce policy: deny weak algorithms; require modern key sizes.
- Prefer **X25519+HKDF → AEAD** for sessions; **Ed25519** for signatures.
- Consider **Hybrid HPKE** in high‑assurance systems.
- Keep XPScerpto Crypto updated; enable hot‑patch gates in production.
- Run self‑tests at startup; monitor failures and rotate keys on compromise.

---

## 15) Troubleshooting

- **PolicyDenied:** The algorithm or key size is disallowed. Loosen the policy or pick a stronger option.
- **BadTag:** AEAD verification failed — reject the data; do not retry with guesses.
- **KeyNotFound / Revoked:** Keyring entry missing or revoked — provision or restore from encrypted backup.
- **ConfigMismatch (modules):** Ensure all translation units use the same module flags (PThreads, sanitizers, etc.).

---

**That’s it!** You now have a practical, production‑minded path to use XPScerpto Crypto safely and efficiently across symmetric, asymmetric, and hybrid cryptography.


---

## Merged from `simd/USAGE_GUIDE.md`

# XPScerpto — Usage Guide (Expanded)
**Version:** v4 • **Generated:** 2025-11-02 11:52 UTC

## 0. Toolchain Requirements
- **C++23** with Modules: Clang ≥ 17 (tested best with 19.x), GCC ≥ 14, MSVC 17.10+.
- Build system: **CMake ≥ 3.31** with explicit Module dependency scanning.
- OS: Linux/Windows/macOS. ARM64 and x86_64 are first-class.

> Avoid precompiled headers that alter `-pthread` or defines across module units. PCH/PCM **config mismatch**
> is a common cause of “cannot be loaded due to configuration mismatch”.

## 1. CMake Integration (Modules)
```cmake
# Top-level
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Example: building a module interface and an implementation unit
add_library(xps_crypto INTERFACE)
target_compile_features(xps_crypto INTERFACE cxx_std_23)

# Consumers import units; ensure same flags for all module producers/consumers:
add_executable(demo_aes_gcm demo_aes_gcm.cpp)
target_link_libraries(demo_aes_gcm PRIVATE xps_crypto)
# IMPORTANT: ensure -pthread, -fPIC, sanitizer flags are consistent for all PCM users.
```

**Tip:** Keep **thread**, **sanitizer**, and **arch** flags identical for any target that reads the same PCM cache.

## 2. Environment Controls
- `XPS_SIMD_CT=1` — force constant‑time posture (exclude non‑CT kernels).
- `XPS_SIMD_AUTOTUNE=0` — disable runtime tuning (pick by static weight).
- `XPS_SIMD_AVX512_DEMOTION=0` — allow AVX‑512 if available (default is demoted).
- `XPS_SIMD_ISA_MASK=0x...` — restrict allowed ISAs (hex bitmask matching the architecture enum).

## 3. Policy API (Optional)
```cpp
import xps.crypto.policy;
using XPScerpto::crypto::policy;

policy::set_constant_time(true);
policy::set_autotune(true);
policy::set_allowed_isa_mask(policy::ALL & ~policy::AVX512);
```

## 4. AES‑GCM Example
```cpp
import xps.crypto.simd.dispatch;
import xps.crypto.alg.aes.gcm;   // registers portable + AESNI + AVX2(+VAES) kernels

void aes_gcm_demo() {
  uint8_t key[16]{}; uint8_t iv[12]{};  // fill securely
  std::vector<uint8_t> aad = { /* ... */ };
  std::vector<uint8_t> plain = { /* ... */ }, cipher(plain.size());
  uint8_t tag[16]{};

  // High-level API (internally resolves best kernel):
  XPScerpto::crypto::aes::gcm::encrypt_128(key, iv, aad.data(), aad.size(),
                                     plain.data(), cipher.data(), plain.size(),
                                     tag);
}
```

## 5. X25519 Example (ECDH)
```cpp
import xps.crypto.simd.dispatch;
import xps.crypto.alg.x25519;

std::array<uint8_t,32> ecdh(const std::array<uint8_t,32>& sk,
                            const std::array<uint8_t,32>& pk_peer) {
  std::array<uint8_t,32> shared{};
  XPScerpto::crypto::x25519::derive_shared(sk.data(), pk_peer.data(), shared.data());
  return shared;
}
```

## 6. Poly1305 Example (MAC)
```cpp
import xps.crypto.alg.poly1305;
std::array<uint8_t,16> mac_poly(const uint8_t key[32],
                                const uint8_t* msg, size_t len) {
  std::array<uint8_t,16> tag{};
  XPScerpto::crypto::poly1305::tag(key, msg, len, tag.data());
  return tag;
}
```

## 7. Diagnostics & Tracing (Dev Only)
```cpp
import xps.crypto.simd.trace;
XPScerpto::crypto::simd::trace::enable(true);
for (auto& ev : XPScerpto::crypto::simd::trace::events()) {
  // ev.op, ev.isa, ev.size, ev.ns
}
```

## 8. Troubleshooting
- **PCM/PCH config mismatch:** ensure **all** targets that read a `.pcm` use the same flags (`-pthread`, sanitizers,
  visibility, exception model).
- **Illegal instruction:** the policy filter prevents unsupported ISA. If you see SIGILL, verify your kernel actually checks
  capabilities before executing (bug in kernel), or restrict ISAs with `XPS_SIMD_ISA_MASK` temporarily.
- **Performance regressions:** set `XPS_SIMD_AVX512_DEMOTION=0` (to try AVX‑512) or `=1` (to avoid it); disable autotune
  to compare static vs tuned selection.

## 9. Minimal Indirection (Manual Resolve)
```cpp
using AesCtrFn = void(*)(const uint8_t*, const uint8_t*, const uint8_t*, uint8_t*, size_t);
extern AesCtrFn aes128_ctr_portable;

AesCtrFn fast = XPScerpto::crypto::simd::dispatch::resolve<AesCtrFn>("AES128-CTR", aes128_ctr_portable);
// Call fast(...) in hot loops
```


---

## Merged from `auto_rotation/USAGE_GUIDE.md`

# USAGE GUIDE — Auto-Rotation
**Version:** 2025-11-01

---

## 1) Quick Start
```cpp
// 1) Import modules
import xps.crypto.keyring.auto_rotation.core;
import xps.crypto.keyring.auto_rotation.policies;
import xps.crypto.keyring.auto_rotation.orchestrator;
import xps.crypto.keyring.auto_rotation.provider.deflt;
import xps.zero_downtime;

// 2) Aliases
namespace ar = XPScerpto::crypto::keyring::auto_rotation;

// 3) Register default provider with hooks (optional)
ar::provider::DefaultKeyProvider prov;
prov.hooks().on_generate = [](const ar::KeyId& id, std::uint32_t v,
                              std::string_view algo, std::optional<std::string_view> params,
                              std::string_view note) -> ar::Result<void> { /* generate in HSM/KMS */ return {{}}; };
ar::register_provider("default", std::make_shared<ar::provider::DefaultKeyProvider>(prov));

// 4) Compose a policy & plan
ar::RotationPlan plan;
plan.key = ar::KeyId{{"payments/jwt"}};
plan.policy_id = "monthly_zdt_7d";
plan.schedule = ar::policies::monthly(std::chrono::hours{0});
plan.grace = std::chrono::hours{24*7}; // Zero-downtime 7 days
plan.provider = "default";
plan.target_suite = "aes-gcm-256"; // via crypto_agile

// 5) Orchestrator
ar::AutoRotationOrchestrator orch;
orch.set_tick(std::chrono::seconds{30});
orch.track(plan);
orch.start();    // std::jthread begins
// … application runs …
orch.stop();
```

## 2) Common Operations
- **Track / untrack key**: `orch.track(plan)`, `orch.untrack(KeyId)`
- **Update tick cadence**: `orch.set_tick(…Sec…)`
- **Subscribe for events**: `ar::subscribe([](const RotationEvent& e){ … })`
- **Provider registry**: `ar::register_provider("name", ptr)`, `ar::get_provider("name")`

## 3) Policies
- **Time-based**: daily/weekly/monthly at a specific UTC hour.
- **Usage-based**: rotate after *N* signatures/decryptions.
- **Mixed**: earliest of (time window, max uses, max age).

## 4) Zero-Downtime (ZDT)
- Use a **grace window** that overlaps old/new versions.
- Ensure clients fetch by **KeyId** + **ResolveLatest()** with fallback to `N` if `N+1` fails.
- Retire `N` only after proving that all traffic has cut over.

## 5) Compliance Gating
- Enable FIPS/approval checks via `compliance` before `activate`.
- Annotate `RotationEvent` with `reason/approver/change_ref` for audit.

## 6) Distributed Mode (Optional)
- Configure a leader election or lease mechanism in `distributed`; only the **active leader** performs rotations.
- Other nodes observe events and keep caches warm.

---

## 7) Troubleshooting
- **“NotFound” errors**: ensure `ErrorCode::NotFound` is mapped by provider; return consistent error codes.
- **Pthread/PCH mismatch**: rebuild all *PCM* after toggling `-pthread`; avoid sharing PCMs across toolchains.
- **Two versions live forever**: grace not expiring—check `policies` and orchestrator tick/cutover conditions.


---

## Merged from `super/USAGE_GUIDE.md`

# USAGE GUIDE — XPS Super Crypto
**Version:** 2025-11-01

---

## 1) Import & Facade
```cpp
import xps.crypto.super_crypto.unified_api;
namespace sc = XPScerpto::crypto::super_crypto;

sc::UnifiedCrypto api = sc::make_default_unified(); // factory
```

## 2) Route Policy Configuration
```cpp
using sc::RoutePolicy;
RoutePolicy p;
p.prefer_fips(true);
p.enable_engine("local_aesgcm", /*weight=*/100);
p.enable_engine("chacha20poly1305", 90);
p.enable_engine("hsm_cluster_a", 80);
api.set_policy(p);
```

## 3) Operations (Illustrative)
```cpp
Bytes ct = api.seal("aes-gcm-256", key_handle, nonce, aad, plaintext);
Bytes pt = api.open("aes-gcm-256", key_handle, nonce, aad, ct);
Bytes mac = api.mac("blake3-256", key, msg);
Bytes out = api.kdf("hkdf-sha256", ikm, salt, info, out_len);
Signature sig = api.sign("ed25519", key_handle, msg);
bool ok = api.verify("ed25519", pub, msg, sig);
```

## 4) Hot-Patch Adapter
```cpp
import xps.crypto.super_crypto.adapter.hot_patch;
sc::HotPatchAdapter hp(api);
hp.stage(patch_capsule);   // signature checked, staged
hp.commit();               // dual-run window then switch
```

## 5) Rotation Adapter
```cpp
import xps.crypto.super_crypto.adapter.rotation;
sc::RotationAdapter rot(api);
rot.bind_keyring("service/payments");
rot.rotate_now("aes-gcm-256"); // immediate rotation path
```

## 6) XPScerpto Bridge Provider
```cpp
import xps.crypto.super_crypto.provider.xpsi_bridge;
auto prov = sc::providers::make_xpsi_bridge(/*config*/);
api.register_provider("xpsi", prov);
```

## 7) Observability
- Metrics: `crypto_ops_total{alg,engine,outcome}`, `crypto_route_latency_seconds`.
- Tracing: route spans with `{alg, tenant, engine, bytes}` attributes.
- Health: engine heartbeats and circuit breakers.