![CI](https://github.com/xpsio/XPScerpto/actions/workflows/ci.yml/badge.svg)
![Link Check](https://github.com/xpsio/XPScerpto/actions/workflows/links.yml/badge.svg)
![Docs](https://github.com/xpsio/XPScerpto/actions/workflows/pages.yml/badge.svg)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# XPScerpto — Modern Cryptography Library (C++20/23 Modules)

**XPScerpto** is a modern, production‑minded cryptography library focused on **speed**, **safety**, and **crypto‑agility**.
It provides a clean separation between **portable** C++ kernels and **accelerated** paths selected via **runtime ISA dispatch**
(AVX2, AVX‑512, NEON, RVV), alongside hardened memory utilities and a security‑first engineering approach.

---

## ✨ Highlights

- **C++20/23 Modules** with clean public interfaces and private internals
- **Runtime SIMD dispatch** (x86/ARM/RISC‑V) with safe fallbacks
- **Hardened memory** utilities (secure buffers, constant‑time helpers, zeroization)
- **Battle‑ready docs**: threat model, failure modes, observability, performance
- **Zero‑downtime hot‑patch flow** for engines under governance control
- **PQC‑Hybrid mindset** toward crypto‑agility (envelope patterns and guidance)

> Note: Examples and namespaces in docs use `xps.crypto.*`. Align import paths with your build and module names.

---

## 📦 Quick Start

```bash
# Configure (build directory recommended)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build -j

# (Optional) Run tests (if enabled)
ctest --test-dir build --output-on-failure
```

**Import / Use (example, adjust to your modules):**
```cpp
import xps.crypto.hash.sha384;  // Example module
#include <vector>
#include <string_view>

int main() {
    using namespace xps::crypto::hash::sha384;
    std::string_view msg = "hello xpScerpto";
    auto digest = SHA384::digest(msg);
    (void)digest; // use digest bytes
    return 0;
}
```

---

## 📚 Documentation Index

- **Usage Guide** → [`docs/USAGE_GUIDE.md`](docs/USAGE_GUIDE.md)
- **Architecture** → [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Security Spec** → [`docs/SECURITY_SPEC.md`](docs/SECURITY_SPEC.md)
- **Memory Security** → [`docs/MEMORY_SECURITY.md`](docs/MEMORY_SECURITY.md)
- **Performance** → [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md)
- **Observability** → [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md)
- **PQC Guide** → [`docs/PQC_GUIDE.md`](docs/PQC_GUIDE.md)
- **Diagrams** → [`docs/DIAGRAMS.md`](docs/DIAGRAMS.md)
- **Workflows** → [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md)
- **Config** → [`docs/CONFIG.md`](docs/CONFIG.md)
- **FAQ** → [`docs/FAQ.md`](docs/FAQ.md)
- **Error Taxonomy** → [`docs/ERROR_TAXONOMY.md`](docs/ERROR_TAXONOMY.md)

---

## 🔒 Security & Responsible Disclosure

Please review **[`SECURITY.md`](SECURITY.md)** and **[`docs/SECURITY_SPEC.md`](docs/SECURITY_SPEC.md)**.
To report a vulnerability, email **security@xpsio.com**. We will coordinate a responsible disclosure timeline.

**Export/Compliance:** You are responsible for compliance with local laws and regulations concerning cryptography.

---

## 🧰 CI & Quality Gates

- **Linux, macOS, Windows** matrix
- **Sanitizers** job (ASan/UBSan) in non‑blocking mode
- **Docs lint** (Mermaid syntax checks, anchors, links)
- **Style & warnings** treated strictly for production profiles

---

## 🤝 Community

- See **[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)** and **[`CONTRIBUTING.md`](CONTRIBUTING.md)**.
- For roadmap and releases: **[`RELEASES_GUIDE.md`](RELEASES_GUIDE.md)** and **[`RELEASE_NOTES.md`](RELEASE_NOTES.md)**.

---

## ⚖️ License

Dual‑licensed — see **[`LICENSE`](LICENSE)** and **[`README-LEGAL.md`](README-LEGAL.md)** for details and attribution.
© 2025 XPSIO Technologies.
