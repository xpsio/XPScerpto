# PQC Guide

<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Table of Contents](#table-of-contents)
- [1. APIs](#1-apis)
- [2. Keys & Sizes](#2-keys--sizes)
- [3. Side‑Channels](#3-sidechannels)
- [4. Migration Strategy](#4-migration-strategy)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [1. APIs](#1-apis)
- [2. Keys & Sizes](#2-keys--sizes)
- [3. Side‑Channels](#3-sidechannels)
- [4. Migration Strategy](#4-migration-strategy)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [1. APIs](#1-apis)
- [2. Keys & Sizes](#2-keys--sizes)
- [3. Side‑Channels](#3-sidechannels)
- [4. Migration Strategy](#4-migration-strategy)
<!-- TOC-END -->


Guidance for using PQC modules (Falcon‑1024, Dilithium‑5) safely in production.

## 1. APIs

- Prefer stable façades that hide internal FFT/NTT details
- Deterministic sign for KATs; randomized sign for production with domain separation

## 2. Keys & Sizes

- Falcon‑1024: large pub/priv; plan storage accordingly
- Dilithium‑5: robust baseline; ensure constant‑time verifiers

## 3. Side‑Channels

- Be wary of data‑dependent memory access in transforms
- Wipe temporary buffers aggressively

## 4. Migration Strategy

- Hybrid mode: classical + PQC signatures during transition
- Version tagged signatures for upgrade paths