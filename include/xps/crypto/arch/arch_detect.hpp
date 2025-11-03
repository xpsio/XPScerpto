#pragma once
// xps::crypto - arch/arch_detect.hpp
// Portable compile-time and runtime feature detection for AVX2/NEON/PCLMUL.

#include <cstdint>
#include <string>

namespace xps::crypto::arch {

struct Features {
    bool avx2{false};
    bool pclmul{false};
    bool aesni{false};
    bool neon{false};
    bool sha3{false}; // placeholder for future
};

// Compile-time hints
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
  #define XPS_ARCH_X86 1
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__)
  #define XPS_ARCH_ARM 1
  #if defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__)
    #define XPS_HAVE_NEON 1
  #endif
#endif

#if defined(__AVX2__) || defined(__AVX__)
  #define XPS_HAVE_AVX 1
#endif

#if defined(__AVX2__)
  #define XPS_HAVE_AVX2 1
#endif

#if defined(__PCLMUL__) || defined(__PCLMULQDQ__)
  #define XPS_HAVE_PCLMUL 1
#endif

#if defined(__AES__)
  #define XPS_HAVE_AESNI 1
#endif

inline Features detect_runtime() {
    Features f{};
#if defined(XPS_ARCH_X86)
  #if defined(__GNUC__) || defined(__clang__)
    // GCC/Clang builtin
    #if defined(__x86_64__) || defined(__i386__)
      if (__builtin_cpu_supports("avx2")) f.avx2 = true;
      if (__builtin_cpu_supports("pclmul")) f.pclmul = true;
      if (__builtin_cpu_supports("aes")) f.aesni = true;
    #endif
  #elif defined(_MSC_VER)
    // MSVC: use cpuid intrinsics at runtime
    int regs[4]{};
    auto cpuid = [&](int leaf, int subleaf){
        __cpuidex(regs, leaf, subleaf);
        return std::make_tuple(regs[0], regs[1], regs[2], regs[3]);
    };
    // AVX2: leaf 7, EBX bit 5
    auto [a,b,c,d] = cpuid(7,0);
    f.avx2   = (b & (1<<5)) != 0;
    f.pclmul = (c & (1<<1)) != 0; // ECX bit 1 on leaf 1 (handled below)
    auto [a1,b1,c1,d1] = cpuid(1,0);
    f.pclmul = f.pclmul || ((c1 & (1<<1)) != 0);
    f.aesni  = (c1 & (1<<25)) != 0;
  #endif
#endif

#if defined(XPS_ARCH_ARM)
  #if defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__)
    f.neon = true;
  #endif
#endif
    return f;
}

inline std::string to_string(const Features& f){
    std::string s;
    s += f.avx2   ? "AVX2 "   : "";
    s += f.pclmul ? "PCLMUL " : "";
    s += f.aesni  ? "AESNI "  : "";
    s += f.neon   ? "NEON "   : "";
    if (s.empty()) s = "generic";
    return s;
}

} // namespace xps::crypto::arch
