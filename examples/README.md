# XPScerpto Examples

Minimal, production-minded examples using the **single umbrella import**:
- `aead_encrypt_decrypt.cpp`
- `ed25519_sign_verify.cpp`
- `x25519_hkdf_aead.cpp`

> Build integration depends on your project setup. If XPScerpto is a CMake target (e.g., `xps_crypto`),
> add these as executables and link to your library target. Otherwise, include the public headers/modules
> per your distribution.

Example CMake snippet (adjust target names/paths):
```cmake
add_executable(example_aead examples/aead_encrypt_decrypt.cpp)
target_link_libraries(example_aead PRIVATE xps_crypto)

add_executable(example_ed25519 examples/ed25519_sign_verify.cpp)
target_link_libraries(example_ed25519 PRIVATE xps_crypto)

add_executable(example_tlsish examples/x25519_hkdf_aead.cpp)
target_link_libraries(example_tlsish PRIVATE xps_crypto)
```
