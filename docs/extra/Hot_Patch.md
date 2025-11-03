# XPScerpto — Hot Patch

<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [1) Executive Summary](#1-executive-summary)
- [2) Goals & Use Cases](#2-goals--use-cases)
- [3) Architecture Overview](#3-architecture-overview)
- [4) Modules Inventory](#4-modules-inventory)
- [5) Patch Lifecycle](#5-patch-lifecycle)
- [6) Zero‑Downtime Apply (ZDT)](#6-zerodowntime-apply-zdt)
- [7) Security, Verification & Signatures](#7-security-verification--signatures)
- [8) Distributed Approval & Governance](#8-distributed-approval--governance)
- [9) Repositories & Installers](#9-repositories--installers)
- [10) Rollback & Last‑Good](#10-rollback--lastgood)
- [11) Crypto‑Agility](#11-cryptoagility)
- [12) Observability (Events & Metrics)](#12-observability-events--metrics)
- [13) External Integrations](#13-external-integrations)
- [14) API Overview (Quick Examples)](#14-api-overview-quick-examples)
  - [Registries](#registries)
  - [Orchestration Plan](#orchestration-plan)
  - [Zero‑Downtime Canary](#zerodowntime-canary)
  - [Fast Rollback](#fast-rollback)
- [15) Operations Runbook](#15-operations-runbook)
- [16) Testing & Compliance](#16-testing--compliance)
- [17) Roadmap](#17-roadmap)
- [18) Appendices](#18-appendices)
  - [A) Manifest Schema (initial guideline)](#a-manifest-schema-initial-guideline)
  - [B) Event Example](#b-event-example)
<!-- TOC-END -->

**Document Version:** 1.0  |  **Last Updated:** 2025-10-27  
**Modules Scope:** xps.crypto.hot_patch.core, xps.crypto.hot_patch.crypto_agile, xps.crypto.hot_patch.distributed, xps.crypto.hot_patch.installer.dynamic, xps.crypto.hot_patch.orchestration, xps.crypto.hot_patch.repo.filesystem, xps.crypto.hot_patch.rollback, xps.crypto.hot_patch.security, xps.crypto.hot_patch.verification, xps.crypto.hot_patch.zero_downtime  
**Status:** Production‑Ready — *Engineering Preview* (formal crypto/security certification pending)

> **Security Advisory**  
> This system is designed with production‑grade practices, but it has not yet undergone formal cryptographic certification.  
> Use in sensitive environments should follow a dedicated security review and compliance validation (e.g., PCI‑DSS, ISO 27001, SOC 2).

---

## Table of Contents
1. Executive Summary  
2. Goals & Use Cases  
3. Architecture Overview  
4. Modules Inventory  
5. Patch Lifecycle  
6. Zero‑Downtime Apply (ZDT)  
7. Security, Verification & Signatures  
8. Distributed Approval & Governance  
9. Repositories & Installers  
10. Rollback & Last‑Good  
11. Crypto‑Agility  
12. Observability (Events & Metrics)  
13. External Integrations  
14. API Overview (Quick Examples)  
15. Operations Runbook  
16. Testing & Compliance  
17. Roadmap  
18. Appendices (Manifest schema, Event example)

---

## 1) Executive Summary
The **Hot Patch System** provides a safe, scalable mechanism to apply binary/module updates to `xps-crypto` components **without downtime**. It supports **staging**, **canary rollout**, **two‑phase activation**, **automatic rollback**, and **distributed approvals**.

**Core values:**
- **Zero‑Downtime**: Two‑phase apply with fine‑grained canary control.  
- **Strong Security**: Manifest and signature verification, trust policies, payload hashing.  
- **Distributed Governance**: Optional quorum approval before activation.  
- **Crypto‑Agility**: Pluggable/replaceable verification algorithms and policies.  
- **Observability**: Structured patch events and hook points for metrics/logging.

---

## 2) Goals & Use Cases
- Patch cryptographic modules or SIMD/ASM paths **live** without service interruption.  
- Ship urgent security fixes using **canary + auto‑rollback**.  
- Roll out new features behind flags with **distributed approvals**.  
- Progressive rollout across clusters/rings and heterogeneous platforms.

---

## 3) Architecture Overview
```
[Repository] --fetch--> [Verification] --security gate--> [Staging] --(ZDT two-phase)--> [Activation]
       |                                        ^                                   |
       |                                        |                                   v
       +-----------[Distributed Approval]-------+----------------------------> [Rollback Index]
```

- **Core**: Patch identifiers (`PatchId`), `PatchPackage`, event model, registries for interfaces.  
- **Verification**: Validates manifest, signatures, payload hash, and trust requirements.  
- **Security Gate**: Policy checks (allow/deny lists, version/component requirements).  
- **Repository**: Fetches manifest/payload (filesystem provider included).  
- **Installer (Dynamic)**: Staging and activation for dynamic libraries (`.so/.dll`).  
- **Zero‑Downtime**: Canary rollout with backoff/jitter and event hooks.  
- **Distributed**: Optional consensus/quorum approval (`xps.consensus`).  
- **Rollback**: Last‑good index per target and safe recovery.  
- **Crypto‑Agility**: Central mapping of crypto policy requirements, switchable at runtime.

---

## 4) Modules Inventory
Detected from the uploaded package:
- `xps.crypto.hot_patch.core`
- `xps.crypto.hot_patch.crypto_agile`
- `xps.crypto.hot_patch.distributed`
- `xps.crypto.hot_patch.installer.dynamic`
- `xps.crypto.hot_patch.orchestration`
- `xps.crypto.hot_patch.repo.filesystem`
- `xps.crypto.hot_patch.rollback`
- `xps.crypto.hot_patch.security`
- `xps.crypto.hot_patch.verification`
- `xps.crypto.hot_patch.zero_downtime`

---

## 5) Patch Lifecycle
1. **Plan** — Define a plan with `PatchId`, `target`, time windows, dependencies.  
2. **Fetch** — Retrieve manifest + payload via `repo.filesystem`.  
3. **Verify** — Validate signatures, payload hash, and policy via `verification` & `security`.  
4. **Stage** — Place payload into a secure staging area via `installer.dynamic`.  
5. **Canary** — Run limited‑scope activation using `zero_downtime` with **event hooks**.  
6. **Activate** — Promote canary to full activation; otherwise **rollback**.  
7. **Publish Events** — Emit structured events (`Planned`, `Fetched`, `Verified`, `Staged`, `CanaryStarted`, `Activated`, `RolledBack`, `Failed`).

**Example manifest fields (illustrative):**
```json
{
  "id": "hotfix-2025-10-27",
  "target": "xps.crypto.hash.sha256",
  "version": "1.2.3",
  "created_at": "2025-10-27T09:00:00Z",
  "signers": ["team-key-1", "build-bot"],
  "payload_hash": "sha256:...",
  "min_platform": "linux-x86_64",
  "metadata": {
    "ticket": "SEC-1234",
    "changelog": "Fix constant-time padding edge case"
  }
}
```

---

## 6) Zero‑Downtime Apply (ZDT)
Powered by `xps.crypto.hot_patch.zero_downtime`:
- **Two‑Phase Apply** — `stage()` then `activate()` with configurable canary window.  
- **Backoff/Jitter** — Smooth load impact and avoid thundering herds.  
- **Event Hooks** — Fine‑grained notifications: `CanaryStart`, `Promote`, `Abort`, `Rollback`.  
- **Policies** — `rollback_on_cancel`, `return_error_on_canary_fail`, configurable `canary_ratio` and intervals.

**Typical options:**
```cpp
using namespace XPScerpto::crypto::hot_patch;
using namespace XPScerpto::crypto::hot_patch::zero_downtime;

ZdtOptions opt{
  .canary_ratio    = 0.05,  // 5%
  .canary_interval = std::chrono::milliseconds{150},
  .backoff_factor  = 1.5,
  .jitter_ratio    = 0.10
};
```

---

## 7) Security, Verification & Signatures
- **Verification** (`xps.crypto.hot_patch.verification`):  
  - Multi‑signature trust (allow trusted authors, require quorum).  
  - Validate `payload_hash` (e.g., SHA‑256) against manifest.  
  - Case‑insensitive hex; flexible trust store entries.
- **Security Gate** (`xps.crypto.hot_patch.security`):  
  - Component/version requirements (`set_requirement`, `satisfies`).  
  - Allowlist/Denylist for identities and components.  
- **Crypto‑Agility**:  
  - Central policy mapping; algorithm/providers can be switched without ABI breaks.

---

## 8) Distributed Approval & Governance
- `xps.crypto.hot_patch.distributed` integrates with `xps.consensus`:  
  - Inject a consensus instance at runtime (`g_consensus`).  
  - Submit a `hot_patch` proposal per activation.  
  - Use `voter_count()` and configurable quorum thresholds.

---

## 9) Repositories & Installers
- **Filesystem Repository** — `xps.crypto.hot_patch.repo.filesystem`:  
  - Layout: `<root>/<patch_id>.json` (manifest) and `<root>/<patch_id>.bin` (payload).  
  - Defined error codes for IO/parse/not‑found/invalid/too‑large.  
- **Dynamic Installer** — `xps.crypto.hot_patch.installer.dynamic`:  
  - Manages a staging directory; safely loads/unloads `.so/.dll`.  
  - Maintains active/previous handles for safe swap during activation.

---

## 10) Rollback & Last‑Good
- **RollbackIndex** remembers the **last good** `PatchId` per target.  
- On canary failure or abort, restore quickly via installer integration.  
- Works with ZDT to ensure safe re‑load and minimal disruption.

---

## 11) Crypto‑Agility
- API for declaring **requirements** per component (algorithms, versions, providers).  
- Central map protected by shared/exclusive locks.  
- Enables gradual migration between algorithms or keys without ABI breaks.

---

## 12) Observability (Events & Metrics)
- Unified patch events via `publish(...)` (see `core`).  
- Recommended integration with Prometheus/ELK.  
- Time‑series logging per target to track activation/failure/rollback.

---

## 13) External Integrations
- **xps.consensus** for quorum approvals.  
- **xps.crypto.types/errors** for `Result<T>` and error codes.  
- **xps.crypto.hash.sha256** (or alternative) to verify `payload_hash`.

---

## 14) API Overview (Quick Examples)

### Registries
```cpp
using namespace XPScerpto::crypto::hot_patch;

register_repository("fs", std::make_shared<FileSystemRepository>(root));
register_verifier("sig",   std::make_shared<DefaultVerifier>(trust_store));
register_security("sec",   std::make_shared<SecurityGate>(policy));
register_installer("dyn",  std::make_shared<DynamicInstaller>(stage_dir));
register_approver("dist",  std::make_shared<DistributedApproval>(consensus));
```

### Orchestration Plan
```cpp
using namespace XPScerpto::crypto::hot_patch;

PatchPlan plan{
  .id        = "hotfix-2025-10-27",
  .target    = "xps.crypto.hash.sha256",
  .repo      = "fs",
  .verifier  = "sig",
  .security  = "sec",
  .installer = "dyn",
  .approver  = "dist"
};

Planner planner;
planner.add_plan(plan);
// Single-run:
planner.run_once("hotfix-2025-10-27");
// Or continuous loop with graceful stop_token:
/*
planner.run_loop(std::stop_token{}, std::chrono::milliseconds{250});
*/
```

### Zero‑Downtime Canary
```cpp
using namespace XPScerpto::crypto::hot_patch;
using namespace XPScerpto::crypto::hot_patch::zero_downtime;

ZdtOptions opt{ .canary_ratio = 0.05 };
auto ok = two_phase_apply(*installer, pkg, payload, opt);
```

### Fast Rollback
```cpp
using namespace XPScerpto::crypto::hot_patch;

rollback::RollbackIndex idx;
idx.set_last_good(plan.target, last_good_patch_id);
auto back = idx.get_last_good(plan.target);
```

---

## 15) Operations Runbook
- **Trust Preparation** — Generate/distribute signing keys; load trust store in `verification`.  
- **Policy Setup** — Maintain allow/deny lists and version requirements (`security`).  
- **Working Directories** — Configure repository root and installer `stage_dir`.  
- **Monitoring** — Register event hooks and export metrics.  
- **Canary Run** — Small scope rollout with close monitoring.  
- **Full Activation** — Promote after thresholds are met; persist **last good**.  
- **Recovery** — Trigger rollback on any failure or abort criteria.

---

## 16) Testing & Compliance
- **Unit Tests** — Signature/hash verification, security gate policies, rollback index, ZDT scenarios.  
- **Integration Tests** — End‑to‑end flow (Fetch → Verify → Stage → Canary → Activate → Rollback).  
- **Compliance** — Audit trail with timestamps, periodic reports, immutable logs.

---

## 17) Roadmap
- Multi‑repository with priority/failover.  
- Multiple manifest signatures + timestamping/OCSP.  
- Encrypted payloads (envelope encryption) + HSM/KMS key management.  
- Unified metrics hooks with `xps.metrics` (Prometheus exporter).

---

## 18) Appendices

### A) Manifest Schema (initial guideline)
- `id` — Patch identifier (unique).  
- `target` — Target component/module.  
- `version` — Patch version.  
- `signers[]` — Allowed signers / trusted authors.  
- `payload_hash` — `sha256:<hex>` (or policy‑defined).  
- `constraints` — Platform/arch/dependencies.  
- `metadata` — Freeform (ticket, changelog, etc.).

### B) Event Example
```json
{
  "type": "Activated",
  "id": "hotfix-2025-10-27",
  "target": "xps.crypto.hash.sha256",
  "reason": "canary_success",
  "ts": "2025-10-27T09:20:31Z"
}
```

---
