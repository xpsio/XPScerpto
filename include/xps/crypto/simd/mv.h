
#ifndef XPS_SIMD_MV_H
#define XPS_SIMD_MV_H

// Portable multi-versioning helpers.
// Use XPS_SIMD_MV on hot functions to let the toolchain generate ISA-specialized clones.
// Falls back to no attribute if unsupported.

#if defined(__GNUC__) || defined(__clang__)
  // GCC and Clang both support target_clones (though feature sets vary).
  // You can trim the list to match your kernels.
  #ifndef XPS_SIMD_TARGET_CLONES_LIST
    #define XPS_SIMD_TARGET_CLONES_LIST "default","sse4.1","avx2","avx512f","aes","pclmul","vaes","vpclmulqdq"
  #endif
  #define XPS_SIMD_MV __attribute__((target_clones(XPS_SIMD_TARGET_CLONES_LIST)))
#else
  #define XPS_SIMD_MV
#endif

// IFUNC helper (ELF platforms, GCC). Choose the best implementation at load time.
#if defined(__GNUC__) && defined(__ELF__) && !defined(__APPLE__) && !defined(_WIN32)
  #define XPS_SIMD_HAVE_IFUNC 1
#else
  #define XPS_SIMD_HAVE_IFUNC 0
#endif

// Example pattern (use in a .cpp/ixx translation unit):
// #if XPS_SIMD_HAVE_IFUNC
// extern "C" void * myfunc_ifunc_resolver(void) {
//   // detect ISA here (cpuid / getauxval / __builtin_cpu_supports)
//   return (best == AVX2) ? (void*)&myfunc_avx2 : (void*)&myfunc_portable;
// }
// __attribute__((ifunc("myfunc_ifunc_resolver"))) void myfunc();
// #endif

#endif // XPS_SIMD_MV_H
