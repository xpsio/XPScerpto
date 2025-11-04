
# XPScerpto — Diagrams 

> **Single-file, production-grade diagrams bundle for GitHub.**
> Covers layered architecture, HNDL threat model, zero-downtime hot patch, runtime dispatch,
> key lifecycle, AEAD flow, PQC-hybrid HPKE, CSRNG/DRBG, build & packaging, telemetry/audit,
> side-channel boundaries, failure modes, **plus merged SIMD and Auto‑Rotation diagrams and Super/Hybrid overview**.

<!-- TOC-BEGIN -->
## Table of Contents
- [Legend & Conventions](#legend--conventions)
- [1) Layered Architecture Overview](#1-layered-architecture-overview)
- [2) “Harvest-Now, Decrypt-Later” (HNDL) Threat Model](#2-harvestnow-decryptlater-hndl-threat-model)
- [3) Zero-Downtime Hot Patch (Live Update) Flow](#3-zero-downtime-hot-patch-live-update-flow)
- [4) Runtime Dispatch Decision Tree (ISA/Feature Probing)](#4-runtime-dispatch-decision-tree-isafeature-probing)
- [5) Key Lifecycle & Rotation](#5-key-lifecycle--rotation)
- [6) AEAD (e.g., AES-GCM/ChaCha20-Poly1305) Data Flow](#6-aead-eg-aes-gcmchacha20-poly1305-data-flow)
- [7) PQC-Hybrid HPKE Envelope](#7-pqc-hybrid-hpke-envelope)
- [8) CSRNG (CTR-DRBG) Entropy & Reseed](#8-csrng-ctr-drbg-entropy--reseed)
- [9) C++ Modules Build & Packaging Pipeline](#9-c-modules-build--packaging-pipeline)
- [10) Telemetry, Logging, and Audit](#10-telemetry-logging-and-audit)
- [11) Side-Channel & Constant-Time Boundaries](#11-side-channel--constant-time-boundaries)
- [12) Failure Modes & Safe Defaults](#12-failure-modes--safe-defaults)
- [Merged from simd/DIAGRAMS.md](#merged-from-simdiagramsmd)
  - [1. SIMD Component Architecture](#1-simd-component-architecture)
  - [2. SIMD Selection Sequence (First Call)](#2-simd-selection-sequence-first-call)
  - [3. SIMD Policy State](#3-simd-policy-state)
  - [4. SIMD CI/CD Flow](#4-simd-cicd-flow)
- [Merged from auto_rotation/DIAGRAMS.md](#merged-from-auto_rotationdiagramsmd)
  - [A) Auto‑Rotation Component Diagram](#a-auto-rotation-component-diagram)
  - [B) Rotation Sequence (ZDT)](#b-rotation-sequence-zdt)
  - [C) Rollback & Guardrails](#c-rollback--guardrails)
- [Merged from super/DIAGRAMS.md](#merged-from-superdiagramsmd)
- [Appendix A — Auto‑discovered files](#appendix-a--auto-discovered-files)
<!-- TOC-END -->

---

## Legend & Conventions

- **Rectangles** = components/services. **Rhombus** = decision. **Cylinders** = stores. **Round** = external systems.
- **CT** = constant-time required. **Wipe** = guaranteed memory wipe.
- **Governance key** = offline/secured approval for high-risk actions.
- **GitHub-safe Mermaid** (ASCII only).

```mermaid
flowchart LR
  classDef ctrl fill:#222,stroke:#666,stroke-width:1px,color:#fff
  classDef comp fill:#046,stroke:#024,stroke-width:1px,color:#fff
  classDef data fill:#444,stroke:#888,stroke-width:1px,color:#fff
  classDef risk fill:#642,stroke:#d85,stroke-width:1px,color:#fff
  A([Control/Policy]):::ctrl --> B[[Components]]:::comp --> C[(Data/Keys)]:::data --> D([Risk Gates]):::risk
```

---

## 1) Layered Architecture Overview

```mermaid
flowchart TB

%% Nodes
L7A[Client Apps]
L7B[API Facade]
L6A[Orchestrator]
L6B[Policy Engine]
L5A[Provider Classic]
L5B[Provider PQC]
L5C[Provider Hybrid]
L4A[AEAD Kernels]
L4B[Curve or Sign Kernels]
L4C[PQC Kernels]
L4D[Hybrid Glue HPKE KDF]
L3A[Dispatch Runtime]
L2A[Hashes]
L2B[MACs]
L2C[RNG CTR_DRBG]
L2D[Memory and Wipes]
L1A[(OS CPU ISA RNG TPM HSM)]

%% Edges
L7A --> L7B
L7B --> L6A
L6A --> L6B
L6A --> L5A
L6A --> L5B
L6A --> L5C
L5A --> L4A
L5A --> L4B
L5B --> L4C
L5C --> L4D
L4A --> L3A
L4B --> L3A
L4C --> L3A
L4D --> L3A
L3A --> L2A
L3A --> L2B
L3A --> L2C
L3A --> L2D
L2A --> L1A
L2B --> L1A
L2C --> L1A
L2D --> L1A
```


---

## 2) “Harvest-Now, Decrypt-Later” (HNDL) Threat Model

```mermaid
flowchart LR
  ADV((Adversary)):::risk -->|Capture Now| STORE[(Ciphertexts)]
  subgraph Today
    U[Apps] --> ENC[Encrypt Classic or Hybrid]
    ENC --> STORE
  end
  subgraph PQ Era
    QP[Quantum Advances]:::risk --> R{{Break Classic?}}
    R -->|Yes| DANGER[HNDL Exposure]
    R -->|No| SAFE[Still Safe]
  end
  subgraph Mitigation
    H1[Hybrid KEM Classic+PQC] --> KDF[CT KDF]
    KDF --> K[AEAD Keys] --> ENC
  end
  classDef risk fill:#642,stroke:#d85,color:#fff
```

---

## 3) Zero-Downtime Hot Patch (Live Update) Flow

```mermaid
sequenceDiagram
  participant Ops as Ops/SRE
  participant Gov as Governance
  participant Repo as Patch Repo
  participant Node as Node
  participant Loader as Hot-Patch Loader
  participant Kern as Engine

  Ops->>Repo: Publish Patch (signed, SBOM, compat)
  Repo-->>Ops: URI + Hash
  Ops->>Gov: Request Approval
  Gov-->>Ops: Approve (threshold/quorum)

  Ops->>Node: Initiate ZDT Update
  Node->>Loader: Fetch + Verify
  Loader->>Loader: Self-tests / KATs / CT checks
  Loader->>Kern: Load as shadow
  Node->>Node: Drain in-flight ops
  Node->>Kern: Atomic swap (old -> new)
  Node-->>Ops: Health OK (canary, SLOs)
  Ops->>Node: Promote to full traffic
  Note over Node,Kern: Rollback kept until TTL
```

---

## 4) Runtime Dispatch Decision Tree (ISA/Feature Probing)

```mermaid
flowchart TB
  P0[Start] --> P1{{Policy Allows HW?}}
  P1 -->|No| Fallback[Select Portable Path]
  P1 -->|Yes| P2{{AVX512?}}
  P2 -->|Yes| D1[AVX512 Kernel]
  P2 -->|No| P3{{AVX2?}}
  P3 -->|Yes| D2[AVX2 Kernel]
  P3 -->|No| P4{{NEON/RVV?}}
  P4 -->|Yes| D3[NEON/RVV Kernel]
  P4 -->|No| Fallback
  D1 --> S1[Self-Test & KAT]
  D2 --> S1
  D3 --> S1
  Fallback --> S1
  S1 --> C1{{Pass?}}
  C1 -->|Yes| Cache[Cache Decision]
  C1 -->|No| Fallback
  Cache --> Use[Return Function Pointers]
```

---

## 5) Key Lifecycle & Rotation

```mermaid
stateDiagram-v2
  [*] --> KeyGen: Strong RNG + KATs
  KeyGen --> Provisioned: Wrapped/Sealed
  Provisioned --> Active: Attested Load
  Active --> RotatePending: Time/Usage/Policy
  RotatePending --> ActiveN1: Dual write/read
  ActiveN1 --> Retired: Deny new encrypts
  Retired --> Destroyed: CT wipe + audit
  Destroyed --> [*]
```

---

## 6) AEAD (e.g., AES-GCM/ChaCha20-Poly1305) Data Flow

```mermaid
sequenceDiagram
  participant App as App
  participant Fac as Facade
  participant Orc as Orchestrator
  participant Vault as Key Vault
  participant Nonce as Nonce Manager
  participant AEAD as AEAD (CT)

  App->>Fac: encrypt(plaintext, AAD, policy)
  Fac->>Orc: Resolve algorithm + key
  Orc->>Vault: Fetch active key
  Vault-->>Orc: Key ref
  Orc->>Nonce: Unique nonce for key
  Nonce-->>Orc: Nonce
  Orc->>AEAD: Seal(key, nonce, aad, pt)
  AEAD-->>Fac: ct + tag
  Fac-->>App: ciphertext package
```

---

## 7) PQC Hybrid HPKE Envelope

```mermaid
flowchart LR

%% Nodes
S[Sender]
H1[Classic HPKE X25519]
H2[HPKE PQC Kyber]
KDF[CT KDF]
K[AEAD Keys]
AE[AEAD Encrypt]
C[Hybrid Envelope]
R[Receiver]
H1R[Decap Classic]
H2R[Decap PQC]
KDFR[CT KDF]
KR[AEAD Keys]
AED[AEAD Decrypt]

%% Edges
S --> H1
S --> H2
H1 --> KDF
H2 --> KDF
KDF --> K
K --> AE
AE --> C
C --> R
R --> H1R
R --> H2R
H1R --> KDFR
H2R --> KDFR
KDFR --> KR
KR --> AED
```


---


## 8) CSRNG CTR‑DRBG Reseed

```mermaid
flowchart TB

%% Nodes
ES[Entropy OS TPM HSM Jitter]
Cond[Condition Hash Accumulator]
Inst[Instantiate CTR_DRBG K V]
Gen{Generate N Bytes}
Out[Output Bytes]
Health[Health Tests]
Done[Return]
Reseed{Reseed Threshold}
Upd[Reseed Mix Entropy]

%% Edges
ES --> Cond
Cond --> Inst
Inst --> Gen
Gen --> Out
Out --> Health
Health --> Gen
Gen --> Done
Out --> Reseed
Reseed --> Upd
Upd --> Gen
Reseed --> Gen
```


---

## 9) C++ Modules Build & Packaging Pipeline

```mermaid
flowchart LR
  Dev[Source .ixx/.cppm] --> PCM[Compile → PCM]
  PCM --> OBJ[Translate → OBJ]
  OBJ --> LIB[Archive → libxpsi_core]
  LIB --> API[xpsi_api]
  LIB --> TESTS[Unit/Perf/KATs]
  TESTS --> Report[Reports + Coverage]
  API --> Pack[Release Artifacts]
```

---

## 10) Telemetry, Logging, and Audit

```mermaid
flowchart TB
  App[App] --> Fac[API Facade]
  Fac --> Tele[Telemetry Collector]
  Tele --> Prom[Prometheus Exporter]
  Tele --> Audit[(Audit Log)]
  Tele --> SecLog[(Security Log)]
  Audit --> Sink[Immutable Storage]
  SecLog --> SIEM[SIEM/SOC]
```

---

## 11) Side-Channel & Constant-Time Boundaries

```mermaid
flowchart LR
  CT1[CT Zone: Symmetric Kernels] --> CT2[CT Zone: Key Schedule]
  CT2 --> CT3[CT Zone: KDF/HKDF]
  CT3 --> CT4[CT Zone: AEAD Tag Check]
  CT4 --> OUT[API Border]
  OUT --> POL[Policy/Orchestrator]
  POL --> IO[IO/Networking]
```

---

## 12) Failure Modes & Safe Defaults

```mermaid
flowchart TB
  F0[Call] --> F1{{Policy violation?}}
  F1 -->|Yes| DENY[Deny + Audit]
  F1 -->|No| F2{{ISA Path Valid?}}
  F2 -->|No| FALL[Portable Fallback]
  F2 -->|Yes| F3{{Self-Tests Pass?}}
  F3 -->|No| FALL
  F3 -->|Yes| F4{{Nonce/Key OK?}}
  F4 -->|No| DENY
  F4 -->|Yes| OK[Proceed]
```

---

## Merged from `simd/DIAGRAMS.md`

### 1. SIMD Component Architecture
```mermaid
flowchart LR
  subgraph Algorithms
    A1[AES-CTR] --> R
    A2[AES-GCM] --> R
    A3[X25519] --> R
    A4[Poly1305] --> R
  end
  subgraph Dispatch
    R[Kernel Registry] --> D[Dispatcher]
    D --> FP[Fastpath Cache]
    D --> CAL[Calibrate]
  end
  subgraph Kernels
    K1[AVX512]:::k --> OUT
    K2[AVX2]:::k --> OUT
    K3[NEON]:::k --> OUT
    K4[RVV]:::k --> OUT
    K5[BASE]:::k --> OUT
  end
  D --> K1
  D --> K2
  D --> K3
  D --> K4
  D --> K5
  classDef k fill:#222,stroke:#888,color:#fff
```

### 2. SIMD Selection Sequence (First Call)
```mermaid
sequenceDiagram
  participant U as User
  participant D as Dispatcher
  participant R as Registry
  participant P as Policy
  participant C as Calibrate
  participant F as Fastpath
  U->>D: request(op, args)
  D->>R: candidates(op)
  R-->>D: kernel list
  D->>P: filter by policy + ISA
  alt multiple candidates and autotune
    D->>C: microbench(bucket sizes)
    C-->>D: winners per bucket
  else
    D-->>D: choose by weight
  end
  D->>F: publish function pointer
  D-->>U: call fn
```

### 3. SIMD Policy State
```mermaid
stateDiagram-v2
  [*] --> Open
  Open --> Strict: enable stricter rules
  Strict --> FIPS: require known-good paths
  FIPS --> Strict: disable FIPS
  Strict --> Open: relax
```

### 4. SIMD CI/CD Flow
```mermaid
flowchart TB
  C[Commit] --> B[Build Modules]
  B --> T[Unit + KAT Tests]
  T --> S[Sanitizers ASan UBSan TSan]
  S --> P[Performance Gates]
  P -->|pass| R[Release Artifact]
  P -->|fail| J[Investigate Hotspots]
```

---

## Merged from `auto_rotation/DIAGRAMS.md`

### A) Auto‑Rotation Component Diagram
```mermaid
flowchart LR
  subgraph Control
    Pol[Rotation Policy]
    Gov[Governance Key]
  end
  subgraph Services
    Sch[Scheduler]
    Rot[Rotator]
    Val[Validator]
    Aud[Audit Sink]
  end
  subgraph Stores
    K[(Key Vault)]
    M[(Metrics)]
  end
  Pol --> Sch
  Gov --> Sch
  Sch --> Rot
  Rot --> Val
  Rot --> K
  Val --> Aud
  Rot --> M
```

### B) Rotation Sequence (ZDT)
```mermaid
sequenceDiagram
participant Pol as Policy
participant Gov as Governance
participant Rot as Rotator
participant Vault as Key_Vault
participant Node as Node
participant Aud as Audit

Pol->>Gov: approve rotation window
Gov-->>Pol: approved
Pol->>Rot: start rotation N_to_N_plus_1
Rot->>Vault: generate N_plus_1 key
Rot->>Node: enable dual write_and_read
Node-->>Rot: ack
Rot->>Node: cutover at T_plus_delta
Node-->>Rot: N_plus_1 primary and N draining
Rot->>Vault: retire N after TTL
Rot->>Node: deny new encrypts on N
Rot->>Aud: append immutable trail
```

### C) Rollback & Guardrails
```mermaid
flowchart TB
  Start --> Gate{{Gov Quorum Met?}} -->|No| Halt[Halt]
  Gate -->|Yes| Validate[Pre-flight Checks]
  Validate -->|Fail| Abort[Abort + Audit]
  Validate -->|Pass| Dual[Dual Write/Read]
  Dual --> Cutover[Cutover Traffic]
  Cutover --> Health{{Health OK?}}
  Health -->|No| Rollback[Rollback to N]
  Health -->|Yes| Finalize[Retire N after TTL]
```

## Super/Hybrid Overview

```mermaid
flowchart LR
%% Nodes
Client[Client]
API[Unified API]
Route[Routing Orchestrator]
Engines[Engines]
Local[Local]
HSM[KMS HSM]
Remote[Remote]
HotPatch[HotPatch Adapter]
Rotation[Rotation Adapter]
```

```mermaid
%% Edges
Client --> API
API --> Route
Route --> Engines
Engines --> Local
Engines --> HSM
Engines --> Remote
HotPatch --- Rotation
HotPatch --> Engines
Rotation --> Engines
```

---

*End of DIAGRAMS.md*
