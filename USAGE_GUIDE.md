# USAGE_GUIDE.md 

## Overview

This guide shows how to use **XPScerpto** in real-world applications. It focuses on a clean, safe, and *production‑grade* developer experience using modern C++ Modules (C++23). You’ll find end‑to‑end recipes for:
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
> Module names below reflect the canonical structure used across XPScerpto. If your local tree exposes a single **facade** (e.g., `import xps.crypto.api;`), you can stick to the facade for most tasks, or import specialized modules when you need lower‑level control.

---

## 1) Requirements & Build Integration

- **Compiler:** Clang ≥ 17 or GCC ≥ 14 with C++23 modules enabled.
- **OS:** Linux/macOS/Windows; x86‑64/ARM64 (SIMD paths selected at runtime).
- **CMake:** `cmake_minimum_required(VERSION 3.31)` recommended.

### CMake (as a subproject)

```cmake
# Top-level CMakeLists.txt (excerpt)
add_subdirectory(external/XPScerpto)

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

using xps::crypto::Bytes;

// Random bytes (CS-PRNG)
Bytes iv = xps::crypto::random_bytes(12);

// Hex/Base64 helpers
std::string b64 = xps::crypto::base64x::encode(iv);
Bytes back = xps::crypto::base64x::decode(b64);
```

> **Secure defaults.** If you call the high-level AEAD helpers without an algorithm hint, the policy engine will select a strong default (e.g., AES‑256‑GCM or ChaCha20‑Poly1305).

---

## 3) AEAD with AAD (AES‑GCM / ChaCha20‑Poly1305)

### High-level (facade)

```cpp
import xps.crypto.api;

using xps::crypto::Bytes;

// 1) Key & nonce
Bytes key   = xps::crypto::random_bytes(32); // AES‑256 / ChaCha20 key
Bytes nonce = xps::crypto::random_bytes(12); // 96-bit recommended

// 2) Plaintext & AAD (not encrypted, but authenticated)
Bytes pt   = Bytes{'H','e','l','l','o'};
Bytes aad  = Bytes{'m','e','t','a'};

// 3) Encrypt (AEAD)
auto enc = xps::crypto::aead::encrypt({
    .algo  = xps::crypto::AEAD::AES_GCM, // or AEAD::CHACHA20_POLY1305
    .key   = key,
    .nonce = nonce,
    .aad   = aad,
    .plain = pt,
});
if (!enc) { /* handle enc.error() */ }

// enc->cipher includes tag (implementation-defined layout)
auto dec = xps::crypto::aead::decrypt({
    .algo   = xps::crypto::AEAD::AES_GCM,
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

xps::crypto::aead::AESGCM cipher;
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

auto [pub, priv] = xps::crypto::ed25519::generate_keypair();

std::vector<std::byte> msg{/*...*/};

auto sig = xps::crypto::ed25519::sign(msg, priv);
bool ok  = xps::crypto::ed25519::verify(msg, sig, pub);
```

> Store private keys encrypted at rest; wipe them from RAM as soon as you can (see §8 Secure Memory).

---

## 5) X25519 ECDH + HKDF → AEAD Session

```cpp
import xps.crypto.x25519.api;
import xps.crypto.kdf.hkdf;
import xps.crypto.aead.aes_gcm;

// Alice
auto [A_pub, A_priv] = xps::crypto::x25519::generate_keypair();
// Bob
auto [B_pub, B_priv] = xps::crypto::x25519::generate_keypair();

// Derive shared secret on each side
auto sA = xps::crypto::x25519::derive_shared(A_priv, B_pub); // 32 bytes
auto sB = xps::crypto::x25519::derive_shared(B_priv, A_pub); // == sA

// Strengthen with HKDF-SHA256 to 32-byte session key
auto session = xps::crypto::hkdf::derive({
  .ikm = sA,
  .salt = std::nullopt,
  .info = std::vector<std::byte>{},
  .length = 32
});

// Use as AEAD key (AES‑256‑GCM for example)
Bytes nonce = xps::crypto::random_bytes(12);
auto enc = xps::crypto::aead::encrypt({
  .algo = xps::crypto::AEAD::AES_GCM,
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

xps::crypto::sha384::StreamingHasher H;
H.update(std::as_bytes(std::span{"Hello "sv}));
H.update(std::as_bytes(std::span{"World"sv}));
auto digest = H.final(); // 48 bytes

std::string hex = xps::crypto::hex::encode(digest);
```

> The SHA‑384 module exposes one‑shot and streaming APIs. The streaming API minimizes copies and is ideal for large files, sockets, and mmap‑backed inputs.

---

## 7) Key Management with Keyring (Rotation & Revocation)

```cpp
import xps.crypto.keyring;
import xps.memory;

// Create an in‑process keyring
xps::crypto::keyring::Keyring kr;

// Generate & register a named key
auto k = xps::crypto::random_bytes(32);
auto id = kr.add("payments/aead", k);

// Policy: rotate this key every 90 days or 2^32 ops (whichever first)
kr.policy("payments/aead").rotate_days(90).max_uses(1ull<<32);

// Export to disk (password protected) for backup
xps::memory::LockedBuffer pwd = xps::memory::make_locked("correct-horse-battery-staple");
kr.export_encrypted("kr.backup", pwd);

// Re‑import elsewhere when bootstrapping a node
auto kr2 = xps::crypto::keyring::Keyring::import_encrypted("kr.backup", pwd);

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
  auto rnd = xps::crypto::random_bytes(32);
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
auto sealed = xps::crypto::hybrid::hpke::seal({
    .recipient = R,
    .aad       = std::vector<std::byte>{},
    .plain     = cek_bytes // content‑encryption key
});

// Recipient opens if *both* sub‑schemes validate (policy dependent)
auto opened = xps::crypto::hybrid::hpke::open({
    .recipient_priv = { .rsa = rsa_priv, .kyber = kyber_priv },
    .bundle         = sealed->bundle
});
```

> Hybrid HPKE mitigates **“harvest‑now, decrypt‑later”** threats by requiring an attacker to break *both* classical and PQC encapsulations.

---

## 10) Error Handling (`std::expected` style)

All high‑level calls return an `expected<T, Error>` (facade) or throw on error (configurable).

```cpp
auto out = xps::crypto::aead::encrypt(args);
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

xps::crypto::policy::set_minimum_key_size({ .rsa_bits = 3072, .aes_bits = 256 });
xps::crypto::policy::deny_algorithms({ "SHA1", "DES", "RC4" });

// At startup: self‑tests & runtime dispatch (SIMD/ISA detection)
xps::crypto::orchestrator::self_test_all();

// Hot‑patch a vulnerable module with zero downtime
xps::crypto::orchestrator::hot_patch("xps.crypto.hash.sha384", "sha384_2025-11-02.signed");
```

> The orchestrator verifies publisher signatures, runs A/B correctness probes, and only flips traffic when the new unit passes gates (**zero_downtime**).

---

## 12) Minimal Sanity Tests (you can copy into your app)

```cpp
// AEAD roundtrip
{
  auto key = xps::crypto::random_bytes(32);
  auto n   = xps::crypto::random_bytes(12);
  auto e = xps::crypto::aead::encrypt({ .key=key, .nonce=n, .plain=Bytes{1,2,3} });
  auto d = xps::crypto::aead::decrypt({ .key=key, .nonce=n, .cipher=e->cipher });
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
- Keep XPSI Crypto updated; enable hot‑patch gates in production.
- Run self‑tests at startup; monitor failures and rotate keys on compromise.

---

## 15) Troubleshooting

- **PolicyDenied:** The algorithm or key size is disallowed. Loosen the policy or pick a stronger option.
- **BadTag:** AEAD verification failed — reject the data; do not retry with guesses.
- **KeyNotFound / Revoked:** Keyring entry missing or revoked — provision or restore from encrypted backup.
- **ConfigMismatch (modules):** Ensure all translation units use the same module flags (PThreads, sanitizers, etc.).

---

**That’s it!** You now have a practical, production‑minded path to use XPScerpto safely and efficiently across symmetric, asymmetric, and hybrid cryptography.
