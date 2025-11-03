# XPScerpto — Modern Cryptography Library (C++20/23 Modules)

XPScerpto is a high‑performance, production‑minded cryptography library built with modern C++ (C++20/23 Modules). 
It focuses on **speed**, **safety**, and **crypto‑agility**, with **runtime ISA dispatch** (AVX2, AVX‑512, NEON, RVV), 
**secure memory primitives**, and a clear separation of **portable** versus **accelerated** kernels.


---

## 📚 Documentation Index

- **Architecture** → [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Usage Guide** → [`docs/USAGE_GUIDE.md`](docs/USAGE_GUIDE.md)
- **Security Spec** → [`docs/SECURITY_SPEC.md`](docs/SECURITY_SPEC.md)
- **Performance** → [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md)
- **Configuration** → [`docs/CONFIG.md`](docs/CONFIG.md)
- **Observability** → [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md)
- **PQC Guide** → [`docs/PQC_GUIDE.md`](docs/PQC_GUIDE.md)
- **Error Taxonomy** → [`docs/ERROR_TAXONOMY.md`](docs/ERROR_TAXONOMY.md)
- **Workflows & Runbooks** → [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md)
- **Diagrams** → [`docs/DIAGRAMS.md`](docs/DIAGRAMS.md)

---

## 🚀 Quick Start

### Toolchain
- **Clang 19+** or **GCC 14+** with C++20 Modules support
- CMake **3.31+**
- Optional: Ninja, ASan/UBSan/TSan, LTO

### CMake (library user)
```cmake
# Consumer project
cmake_minimum_required(VERSION 3.31)
project(myapp LANGUAGES CXX)

# Assuming XPScerpto is installed or add_subdirectory'd
find_package(XPScerpto CONFIG REQUIRED)

add_executable(demo main.cpp)
target_link_libraries(demo PRIVATE xps.crypto)        # umbrella
# Or granular:
# target_link_libraries(demo PRIVATE xps.crypto.hash.sha384 xps.crypto.kdf.hkdf xps.crypto.aead.aes_gcm)
```

### Example: SHA‑384 + HKDF + AES‑GCM
```cpp
import xps.crypto.hash.sha384;
import xps.crypto.kdf.hkdf;
import xps.crypto.aead.aes_gcm;
import xps.crypto.utils.memory; // LockedBuffer, secure_erase

using namespace xps::crypto;

int main() {
    // Hash
    const unsigned char msg[] = "hello xp";
    auto d = hash::sha384::digest(msg, sizeof(msg)-1);

    // HKDF‑SHA384 derive 32‑byte key
    unsigned char prk[48];
    kdf::hkdf::extract(hash::sha384::hmac, /*salt=*/nullptr, 0, msg, sizeof(msg)-1, prk, sizeof(prk));
    unsigned char key[32];
    kdf::hkdf::expand(hash::sha384::hmac, prk, sizeof(prk), /*info=*/"ctx", 3, key, sizeof(key));

    // AES‑GCM encrypt
    unsigned char iv[12]{{}}; // example only
    unsigned char ct[64]{{}}, tag[16]{{}};
    aead::aes_gcm::seal(key, sizeof(key), iv, sizeof(iv), /*aad*/nullptr,0, msg, sizeof(msg)-1, ct, tag);
}
```

---

## 🧰 Continuous Integration

- Matrix: **Linux**, **macOS**, **Windows**
- Sanitizers job: **ASan/UBSan** (non‑blocking)
- Mermaid linter for docs (no `note over`, no `|label|` on edges, no parentheses in node labels)

---

## 👥 Community & Policies

- Security policy: see **`docs/SECURITY_SPEC.md`**
- Responsible disclosure: `security@yourdomain.tld`
- Code of Conduct / Contributing: add your own files or link to organization policies.
