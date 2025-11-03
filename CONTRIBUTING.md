# Contributing — XPScerpto
Thanks for considering a contribution!

## Getting Started
- Toolchain: **CMake ≥ 3.31**, **Clang ≥ 17** (preferred) or **GCC ≥ 13**, **Ninja**.
- Build:
  ```bash
  cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
  cmake --build build -j
  ctest --test-dir build --output-on-failure
  ```

## Coding Guidelines
- **C++23** with **Modules**. Keep interfaces in `.ixx`, implementations in `.cppm` where applicable.
- Use **`xps::expected`** for no‑exceptions paths; throw `api::crypto_error` only when exceptions are enabled.
- Constant‑time where relevant; avoid secret‑dependent branching.
- Prefer `SecureBuffer/LockedBuffer` for key material; call `secure_wipe`.

## Commit Messages
- Conventional style: `feat:`, `fix:`, `docs:`, `perf:`, `refactor:`, `test:`, `build:`.
- Reference issues like `#123` where appropriate.

## PR Checklist
- [ ] Code compiles with Clang and GCC
- [ ] Tests updated/added; `ctest` green
- [ ] Docs updated (README/USAGE/SECURITY if impacted)
- [ ] No secrets in logs; sensitive data redacted
- [ ] Mermaid diagrams follow GitHub‑safe style (no `|label|`, no parentheses in node labels)

## Running Examples
See **examples/**; add local targets and link against your library target (e.g., `xps_crypto`).

## Communication
- Please read **CODE_OF_CONDUCT.md**.
- Security issues → **SECURITY.md** (do not open public issues for vulnerabilities).
