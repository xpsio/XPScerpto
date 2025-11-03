# Error Taxonomy

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