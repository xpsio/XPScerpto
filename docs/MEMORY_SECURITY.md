# MEMORY_SECURITY — XPScerpto
**Version:** 1.0 • **Date:** 2025-11-03

## 1. Secure Buffers
- `SecureBuffer` / `LockedBuffer` RAII for key material.
- Zeroization on destruction (`secure_wipe`); copy minimized.

## 2. Locking Semantics (per OS)
| OS | Mechanism | Notes |
|----|-----------|-------|
| Linux | `mlock` | may require limits; fallback warning |
| macOS | `mlock` | similar to Linux |
| Windows | `VirtualLock` | privileges/quotas apply |

## 3. Wipe & Reuse
- Use constant‑time wipe where possible; avoid compiler elision.
- Avoid moving secrets across threads unchecked; prefer pinned buffers.

## 4. Pitfalls
- **fork**: duplicated secrets in child; re‑init RNG and wipe parent copies.
- **Swap/OOM**: ensure locked pages; handle allocation failures gracefully.