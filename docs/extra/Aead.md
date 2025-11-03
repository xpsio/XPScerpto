# XPScerpto — Aead

<!-- TOC-BEGIN -->
## Table of Contents

- [Executive Summary](#executive-summary)
  - [Key Features](#key-features)
- [Table of Contents](#table-of-contents)
- [Quick Start](#quick-start)
  - [Encrypt / Decrypt (Unified Pattern)](#encrypt--decrypt-unified-pattern)
- [API Overview](#api-overview)
- [Algorithm Profiles](#algorithm-profiles)
  - [AES‑GCM (if present)](#aesgcm-if-present)
  - [ChaCha20‑Poly1305 (if present)](#chacha20poly1305-if-present)
  - [AES‑GCM‑SIV (if present)](#aesgcmsiv-if-present)
  - [OCB3 (if present)](#ocb3-if-present)
- [Integration (CMake/Modules)](#integration-cmakemodules)
- [Security Notes](#security-notes)
- [Performance Notes](#performance-notes)
- [Troubleshooting](#troubleshooting)
- [Detected Modules](#detected-modules)
<!-- TOC-END -->

**Document Version:** 1.0 &nbsp;|&nbsp; **Last Updated:** 2025-10-26  
**Status:** **Production‑Lean (Engineering Preview)**

> **Security Advisory**  
> This AEAD suite has not undergone formal certification. Use in controlled environments; review nonce policies and key management carefully.

---

## Executive Summary
The XPS AEAD Suite provides modern **Authenticated Encryption with Associated Data** for your crypto stack with a clean C++23/26 Modules interface.
It supports multiple algorithms behind a unified API, focusing on performance, safety, and clear misuse guidance.

### Key Features
- **Unified AEAD API** with associated data (AAD), detached/combined tag modes, and zero‑copy spans.
- **AES‑GCM (128/256)** — NIST SP 800‑38D compliant (nonce‑unique).
- **ChaCha20‑Poly1305** — RFC 8439 (IETF) profile with 96‑bit nonce.

---

## Table of Contents
1. [Quick Start](#quick-start)  
2. [API Overview](#api-overview)  
3. [Algorithm Profiles](#algorithm-profiles)  
4. [Integration (CMake/Modules)](#integration-cmakemodules)  
5. [Security Notes](#security-notes)  
6. [Performance Notes](#performance-notes)  
7. [Troubleshooting](#troubleshooting)  
8. [Detected Modules](#detected-modules)  

---

## Quick Start

### Encrypt / Decrypt (Unified Pattern)
```cpp
#include <array>
#include <vector>
#include <span>
#include <cstdint>
#include <string_view>

// Import the specific module you use, e.g. AES‑GCM or ChaCha20‑Poly1305
import xps.crypto.aead.aes_gcm;            // if present
import xps.crypto.aead.chacha20_poly1305;  // if present

using bytes = std::vector<std::uint8_t>;

int main() {
    using namespace XPScerpto::crypto::aead;

    // Example chooses ChaCha20‑Poly1305 if available, otherwise AES‑GCM.
    // Adjust names to your exact modules.
    constexpr bool prefer_chacha = true;

    // --- inputs ---
    bytes key(32, 0x11);   // 32‑byte key (ChaCha20‑Poly1305). For AES‑GCM use 16/32 bytes.
    bytes nonce(12, 0x22); // 96‑bit nonce (IETF). For GCM, 96‑bit is recommended.
    bytes aad = {'h','e','a','d','e','r'};
    bytes plaintext = {'s','e','c','r','e','t'};

    // --- encrypt (combined) ---
    bytes ciphertext;
    bytes tag(16); // 16‑byte tag (both GCM and ChaCha20‑Poly1305)

    if (prefer_chacha) {
        // chacha20_poly1305::seal_combined(dst, tag, key, nonce, aad, plaintext)
        ciphertext = chacha20_poly1305::seal_combined(key, nonce, aad, plaintext, /*tag_len=*/16);
    } else {
        // aes_gcm::seal_combined(dst, tag, key, nonce, aad, plaintext)
        ciphertext = aes_gcm::seal_combined(key, nonce, aad, plaintext, /*tag_len=*/16);
    }

    // --- decrypt (combined) ---
    bytes decrypted;
    bool ok = false;
    if (prefer_chacha) {
        ok = chacha20_poly1305::open_combined(decrypted, key, nonce, aad, ciphertext);
    } else {
        ok = aes_gcm::open_combined(decrypted, key, nonce, aad, ciphertext);
    }

    return ok ? 0 : 1;
}
```

> **Detached vs Combined:**  
> - *Combined* = `ciphertext || tag` in one buffer.  
> - *Detached* = `ciphertext` and `tag` stored separately. Both modes are typically exposed.

---

## API Overview

**Concepts (typical):**
- `seal_detached(out_ct, out_tag, key, nonce, aad, plaintext)`  
- `open_detached(out_pt, key, nonce, aad, ciphertext, tag)`  
- `seal_combined(key, nonce, aad, plaintext, tag_len=16) -> bytes`  
- `open_combined(out_pt, key, nonce, aad, ciphertext_and_tag) -> bool`

**Spans & zero‑copy:** Implementations may use `std::span<std::uint8_t>` to avoid copies. Ensure destination buffers have sufficient capacity.

---

## Algorithm Profiles

### AES‑GCM (if present)
- **Module:** `xps.crypto.aead.aes_gcm` (typical naming)  
- **Key sizes:** 16 or 32 bytes (AES‑128/256)  
- **Nonce:** 12 bytes (96‑bit recommended); **must be unique per key**  
- **Tag:** 16 bytes recommended (12–16 range)  
- **Refs:** NIST SP 800‑38D

**Misuse warning:** Reusing a (key, nonce) pair in GCM is catastrophic. Use a robust nonce allocator (CTR/sequence) and never wrap counters.

### ChaCha20‑Poly1305 (if present)
- **Module:** `xps.crypto.aead.chacha20_poly1305` (typical naming)  
- **Key:** 32 bytes  
- **Nonce:** 12 bytes (IETF)  
- **Tag:** 16 bytes  
- **Refs:** RFC 8439

**Strengths:** Excellent performance on CPUs without AES acceleration; simple, robust design.

### AES‑GCM‑SIV (if present)
- **Module:** `xps.crypto.aead.aes_gcm_siv`  
- **Nonce:** 12 bytes; **nonce‑misuse resistant** (safer if uniqueness may fail)  
- **Refs:** RFC 8452

### OCB3 (if present)
- **Module:** `xps.crypto.aead.ocb`  
- **Note:** Check patent/licensing constraints for commercial deployment.

---

## Integration (CMake/Modules)

```cmake
# Example: expose AEAD modules (adjust paths)
add_library(xps.crypto.aead INTERFACE)

target_sources(xps.crypto.aead INTERFACE
  FILE_SET cxx_modules TYPE CXX_MODULES FILES
    aead/xps.crypto.aead.aes_gcm.ixx
    aead/xps.crypto.aead.chacha20_poly1305.ixx
    # aead/xps.crypto.aead.aes_gcm_siv.ixx
    # aead/xps.crypto.aead.ocb.ixx
)

# Consumer
add_executable(aead_demo src/main.cpp)
target_link_libraries(aead_demo PRIVATE xps.crypto.aead)
```

**Build tips:**
- Ensure low‑level primitives (AES, GHASH, ChaCha20, Poly1305) are available as module dependencies.  
- If SIMD is used, add runtime dispatch guards for portability.

---

## Security Notes

- **Keys:** Always derive from a KDF (HKDF/Argon2id) and store using secure keyrings.  
- **Nonces:** For GCM/ChaCha20‑Poly1305 use a 96‑bit counter or sequence allocator; never reuse per key.  
- **AAD:** Include protocol headers/context to prevent cross‑protocol attacks.  
- **Clearing:** Zero sensitive buffers after use when feasible.  
- **Side‑channels:** Prefer constant‑time Poly1305/GHASH; avoid data‑dependent branches.

---

## Performance Notes

- AES‑GCM benefits from AES‑NI and PCLMULQDQ; ChaCha20‑Poly1305 often wins on non‑AES‑NI hardware.  
- Aggregate small messages in batches to amortize setup costs.  
- Consider parallel GHASH (for large payloads) and precomputed H tables.

---

## Troubleshooting

**Decryption fails (tag mismatch):**
- Verify key/nonce identity on both ends; confirm AAD is identical.  
- Check combined vs detached mode confusion.  
- Ensure no accidental truncation of tag.

**`module ... not found` during build:**
- Ensure CMake targets expose public modules via `FILE_SET cxx_modules` and consumer links them.  
- Precompile dependent primitives before AEAD modules.

---

## Detected Modules
- `xps.crypto.aead.aes_gcm`
- `xps.crypto.aead.chacha20poly1305`
- `xps.crypto.aead.xchacha20_poly1305`

---

**Contact:** xpsio Crypto Team <crypto-team@xpsio.com>  
**Classification:** xpsio Internal — AEAD Suite