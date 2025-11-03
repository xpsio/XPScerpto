# XPScerpto — Fips1403 Mapping

<!-- TOC-BEGIN -->
## Table of Contents

- [Algorithm Tables (Illustrative)](#algorithm-tables-illustrative)
  - [Approved / Allowed (Default)](#approved--allowed-default)
  - [Allowed but Non‑Approved (Use‑case Dependent)](#allowed-but-nonapproved-usecase-dependent)
- [Self‑Test Inventory (Examples)](#selftest-inventory-examples)
- [Finite State Model (High‑level)](#finite-state-model-highlevel)
- [Documentation & Artifacts (Pointers)](#documentation--artifacts-pointers)
- [Gaps & Actions (If pursuing formal validation)](#gaps--actions-if-pursuing-formal-validation)
<!-- TOC-END -->


> Scope: *Software‑only cryptographic module* (no physical tamper evidence). This mapping summarizes how XPScerpto Crypto aligns with FIPS 140‑3. Status legend: ✓ Implemented · ◇ Partial · ○ Planned.

| FIPS 140‑3 Area | Requirement (Summary) | Evidence in XPScerpto Crypto | Status |
|---|---|---|---|
| **Module Specification** | Clearly define module boundary, version, services, APIs, approved algorithms. | Module docset (ARCHITECTURE.md, SECURITY_SPEC), versioned APIs (e.g., `xps.crypto.api`), algorithm registry & policy manifest. | ✓ |
| **Ports & Interfaces** | Identify logical interfaces and data/control flows. | API reference; separation of data (plaintext/ciphertext), control, status; no direct key export without wrapping. | ✓ |
| **Roles, Services & Auth** | Define Crypto‑Officer / User roles; list services and access control; authenticate roles when applicable. | Policy engine with service tagging (Encrypt/Sign/Derive), admin policy file for enabling/disabling algorithms; audit trails for privileged actions. | ◇ |
| **Finite State Model** | Provide FSM with power‑up, self‑test, operational, error states. | Self‑test manager: power‑up KATs → “Operational” or “Error/Disabled”; conditional test hooks. State diagram in DIAGRAMS.md. | ✓ |
| **Physical Security** | Tamper evidence for hardware modules. | N/A (software module). Documented limitation; recommend OS/container hardening and HSM integration when required. | ✓ |
| **Operational Environment** | Specify supported OS/CPU; single‑user vs multi‑user; integrity protections. | Supported platforms list; signed module updates; integrity checks before dynamic load; reproducible builds in CI. | ✓ |
| **Cryptographic Key Management** | Key generation, entry/output, storage, zeroization; key states and lifecycles. | Keyring: generation with CSPRNG, labeled usages, rotation/revocation, password‑wrapped at rest; `SecureBuffer` zeroization; manifest of key states. | ✓ |
| **EMI/EMC** | Emissions/compatibility (hardware). | Not applicable to software‑only module; deployment guidance references platform certification when relevant. | ✓ |
| **Self‑Tests** | Power‑up KATs for approved algorithms; conditional tests (pairwise, continuous DRBG). | Self‑test harness with AES/SHA/HMAC/DRBG/Ed25519 KATs; pairwise key tests; DRBG continuous tests; fail‑safe mode on error. | ✓ |
| **Design Assurance** | Configuration management, code review, secure SDLC, documented build. | Version control; code review workflow; CI with sanitizers; deterministic builds; documented build options and flags. | ◇ |
| **Mitigation of Other Attacks** | Document mitigations (timing/cache, fault injection). | Constant‑time discipline; memory locking and zeroization; policy to avoid variable‑latency ops on secrets; negative testing and fuzzing. | ✓ |

---

## Algorithm Tables (Illustrative)

### Approved / Allowed (Default)
- AES‑GCM (128/192/256), SHA‑256/384/512, SHA‑3, HMAC(SHA‑2/3), CTR‑DRBG, RSA‑PSS (≥ 3072), ECDH/ECDSA (policy), Ed25519.

### Allowed but Non‑Approved (Use‑case Dependent)
- ChaCha20‑Poly1305, BLAKE2/BLAKE3, SHAKE128/256, PQC (Kyber, Dilithium, Falcon) — enabled via policy or for hybrid.

> Note: Final “Approved” status depends on the certification boundary chosen for a given validation submission and NIST/CMVP guidance at the time of filing.

---

## Self‑Test Inventory (Examples)
- AES‑GCM KAT (encrypt/decrypt), SHA‑2/3 KAT, HMAC KAT, CTR‑DRBG instantiate/reseed/generate KAT + continuous test, Ed25519 sign/verify KAT, X25519 shared‑secret KAT, HKDF KAT.
- Conditional: pairwise consistency tests on RSA/ECC keygen; DRBG continuous tests; load‑time signature verification for hot‑patch modules.

---

## Finite State Model (High‑level)
```
+-----------+      KATs pass       +-------------+
|  Power‑Up |  ------------------> | Operational |
+-----------+                      +-------------+
      |                                   |
      | KAT fail / integrity fail         | Policy change / update
      v                                   v
+-----------+ <--------------------- +-------------+
|  Error    |        Recovery         |  Update    |
+-----------+  (admin only / signed)  +-------------+
```

---

## Documentation & Artifacts (Pointers)
- SECURITY_SPEC(.en).md (this file), ARCHITECTURE.md, USAGE_GUIDE.md
- DIAGRAMS.md: FSM and data‑flow diagrams (ports & interfaces)
- WORKFLOWS.md: key lifecycle (gen → use → rotate → revoke → destroy)
- Test vectors (KAT JSON) and CI logs (self‑tests)
- Policy manifest: allowed algorithms, key sizes, and runtime switches

---

## Gaps & Actions (If pursuing formal validation)
- Roles/Services formalization (service tables, role authentication details) — **Partial**.
- Design Assurance package (traceability matrix, full config mgmt evidence) — **Partial**.
- Define exact **validation boundary** (what’s in/out for CMVP) and produce the Security Policy document per CMVP template.