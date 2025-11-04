# Error Taxonomy

<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [Table of Contents](#table-of-contents)
- [1. Categories](#1-categories)
- [2. Mapping Examples](#2-mapping-examples)
- [3. Guidance](#3-guidance)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [Table of Contents](#table-of-contents)
- [1. Categories](#1-categories)
- [2. Mapping Examples](#2-mapping-examples)
- [3. Guidance](#3-guidance)
<!-- TOC-END -->


<!-- TOC-BEGIN -->
## Table of Contents

- [1. Categories](#1-categories)
- [2. Mapping Examples](#2-mapping-examples)
- [3. Guidance](#3-guidance)
<!-- TOC-END -->


A consistent set of error codes maps to `std::expected<T, ErrorCode>` results.

## 1. Categories

- `ERR_ARG_INVALID`
- `ERR_STATE`
- `ERR_CRYPTO_FAIL`
- `ERR_LENGTH`
- `ERR_UNSUPPORTED`
- `ERR_PLATFORM`
- `ERR_IO`
- `ERR_INTERNAL`

## 2. Mapping Examples

- AES‑GCM tag mismatch → `ERR_CRYPTO_FAIL`
- Unsupported ISA path → `ERR_UNSUPPORTED`
- Buffer overlap in memcpy → `ERR_ARG_INVALID`

## 3. Guidance

- Avoid exceptions for expected failures
- Use narrow, actionable messages; keep PII out of logs