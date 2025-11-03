module; // ─────────────────────────────────────────────────────────────────────
// Global module fragment — standard headers (not exported)
// ─────────────────────────────────────────────────────────────────────────────
#include <cstdint>
#include <cstddef>   // std::byte, std::to_integer
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <algorithm>
#include <bit>       // std::endian

// Intrinsics for SIMD kernels
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #include <immintrin.h>
#endif
#if defined(__aarch64__) || defined(__ARM_NEON)
  #include <arm_neon.h>
#endif

// ─────────────────────────────────────────────────────────────────────────────
export module xps.internal.base64;

// Project modules (imports must immediately follow the module declaration)
import xps.crypto.internal.common;
import xps.expected;                      // xps::expected<T, std::string> / xps::unexpected<T>
import xps.crypto.simd.dispatch;          // ISA enum + runtime capabilities
import xps.crypto.simd.dispatch.kernels;  // kernels::{register_kernel, resolve_kernel}

// ─────────────────────────────────────────────────────────────────────────────
// internal.base64 — High-performance Base64 (RFC 4648) with:
//   • Standard & URL-safe alphabets, optional padding and line wrapping
//   • STRICT URL enforcement (forbid '+'/'/', require '-'/'_' if non-empty)
//   • SIMD mapping paths for URL<->Standard (AVX512BW/AVX2/NEON) — decoding only
//   • Streaming encoder/decoder
//   • 48→64 mega-unroll for encoding + a tight ≤32B path
//   • Rejects length % 4 == 1 for unpadded inputs (per spec)
// ─────────────────────────────────────────────────────────────────────────────

// ------------------------------ Internals (not exported) ---------------------
namespace xps::intx::detail {

  inline constexpr char ALPH_STD[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  inline constexpr char ALPH_URL[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  // Decoding table (256 entries):
  //  0..63 → valid sextet, 0x80 → invalid, 0x40 → padding '='
  struct DecTable {
    unsigned char t[256]{};
    constexpr DecTable(const char* alphabet) : t{} {
      for (auto& v : t) v = 0x80; // invalid by default
      for (int i = 0; i < 64; ++i)
        t[ static_cast<unsigned char>(alphabet[i]) ] = static_cast<unsigned char>(i);
      t[ static_cast<unsigned char>('=') ] = 0x40; // padding marker
    }
  };

  inline constexpr DecTable DEC_STD{ALPH_STD};
  inline constexpr DecTable DEC_URL{ALPH_URL};

  inline constexpr bool is_space(unsigned char c) noexcept {
    return c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='\f' || c=='\v';
  }

  inline bool has_space(std::string_view s) noexcept {
    for (unsigned char c : s) if (is_space(c)) return true;
    return false;
  }

  inline constexpr const char* alphabet(bool is_standard) noexcept {
    return is_standard ? ALPH_STD : ALPH_URL;
  }

  // Encoded length without wrapping. If pad=false, output shrinks for leftovers.
  inline constexpr std::size_t enc_len_no_wrap(std::size_t n, bool pad) noexcept {
    const std::size_t full = (n/3)*4;
    const std::size_t rem  = n%3;
    if (pad) return full + (rem ? 4 : 0);
    return full + (rem==0 ? 0 : (rem+1)); // 1→2, 2→3
  }

  inline constexpr std::size_t lines_extra(std::size_t chars, std::size_t line_len, bool crlf) noexcept {
    if (line_len==0 || chars==0) return 0;
    const std::size_t lines  = (chars + line_len - 1) / line_len; // ceil
    if (lines<=1) return 0;
    const std::size_t breaks = lines - 1;
    return breaks * (crlf ? 2 : 1);
  }

  // ───────────── SIMD mapping kernels (Standard↔URL) + registry glue ─────────
  using map_fn = void(*)(char* dst, const char* src, std::size_t n);

  // Scalar fallbacks
  inline void map_std2url_scalar(char* dst, const char* src, std::size_t n) {
    for (std::size_t i=0;i<n;++i) {
      char c = src[i];
      if (c == '+') c = '-';
      else if (c == '/') c = '_';
      dst[i] = c;
    }
  }
  inline void map_url2std_scalar(char* dst, const char* src, std::size_t n) {
    for (std::size_t i=0;i<n;++i) {
      char c = src[i];
      if (c == '-') c = '+';
      else if (c == '_') c = '/';
      dst[i] = c;
    }
  }

  // AVX2 32-byte
  #if defined(__AVX2__)
  inline void map_std2url_avx2(char* dst, const char* src, std::size_t n) {
    const __m256i plus  = _mm256_set1_epi8('+');
    const __m256i slash = _mm256_set1_epi8('/');
    const __m256i dash  = _mm256_set1_epi8('-');
    const __m256i under = _mm256_set1_epi8('_');
    std::size_t i=0;
    for (; i+32<=n; i+=32) {
      __m256i v = _mm256_loadu_si256((const __m256i*)(src+i));
      __m256i eqp = _mm256_cmpeq_epi8(v, plus);
      __m256i eqs = _mm256_cmpeq_epi8(v, slash);
      v = _mm256_blendv_epi8(v, dash,  eqp);
      v = _mm256_blendv_epi8(v, under, eqs);
      _mm256_storeu_si256((__m256i*)(dst+i), v);
    }
    for (; i<n; ++i) { char c=src[i]; if(c=='+') c='-'; else if(c=='/') c='_'; dst[i]=c; }
  }
  inline void map_url2std_avx2(char* dst, const char* src, std::size_t n) {
    const __m256i dash  = _mm256_set1_epi8('-');
    const __m256i under = _mm256_set1_epi8('_');
    const __m256i plus  = _mm256_set1_epi8('+');
    const __m256i slash = _mm256_set1_epi8('/');
    std::size_t i=0;
    for (; i+32<=n; i+=32) {
      __m256i v = _mm256_loadu_si256((const __m256i*)(src+i));
      __m256i eqd = _mm256_cmpeq_epi8(v, dash);
      __m256i equ = _mm256_cmpeq_epi8(v, under);
      v = _mm256_blendv_epi8(v, plus,  eqd);
      v = _mm256_blendv_epi8(v, slash, equ);
      _mm256_storeu_si256((__m256i*)(dst+i), v);
    }
    for (; i<n; ++i) { char c=src[i]; if(c=='-') c='+'; else if(c=='_') c='/'; dst[i]=c; }
  }
  #endif

  // AVX512BW 64-byte
  #if defined(__AVX512BW__)
  inline void map_std2url_avx512(char* dst, const char* src, std::size_t n) {
    const __m512i plus  = _mm512_set1_epi8('+');
    const __m512i slash = _mm512_set1_epi8('/');
    const __m512i dash  = _mm512_set1_epi8('-');
    const __m512i under = _mm512_set1_epi8('_');
    std::size_t i=0;
    for (; i+64<=n; i+=64) {
      __m512i v = _mm512_loadu_si512((const void*)(src+i));
      __mmask64 mp = _mm512_cmpeq_epi8_mask(v, plus);
      __mmask64 ms = _mm512_cmpeq_epi8_mask(v, slash);
      v = _mm512_mask_mov_epi8(v, mp, dash);
      v = _mm512_mask_mov_epi8(v, ms, under);
      _mm512_storeu_si512((void*)(dst+i), v);
    }
    for (; i<n; ++i) { char c=src[i]; if(c=='+') c='-'; else if(c=='/') c='_'; dst[i]=c; }
  }
  inline void map_url2std_avx512(char* dst, const char* src, std::size_t n) {
    const __m512i dash  = _mm512_set1_epi8('-');
    const __m512i under = _mm512_set1_epi8('_');
    const __m512i plus  = _mm512_set1_epi8('+');
    const __m512i slash = _mm512_set1_epi8('/');
    std::size_t i=0;
    for (; i+64<=n; i+=64) {
      __m512i v = _mm512_loadu_si512((const void*)(src+i));
      __mmask64 md = _mm512_cmpeq_epi8_mask(v, dash);
      __mmask64 mu = _mm512_cmpeq_epi8_mask(v, under);
      v = _mm512_mask_mov_epi8(v, md, plus);
      v = _mm512_mask_mov_epi8(v, mu, slash);
      _mm512_storeu_si512((void*)(dst+i), v);
    }
    for (; i<n; ++i) { char c=src[i]; if(c=='-') c='+'; else if(c=='_') c='/'; dst[i]=c; }
  }
  #endif

  // NEON 16-byte
  #if defined(__aarch64__) || defined(__ARM_NEON)
  inline void map_std2url_neon(char* dst, const char* src, std::size_t n) {
    const uint8x16_t vplus  = vdupq_n_u8(static_cast<uint8_t>('+'));
    const uint8x16_t vslash = vdupq_n_u8(static_cast<uint8_t>('/'));
    const uint8x16_t vdash  = vdupq_n_u8(static_cast<uint8_t>('-'));
    const uint8x16_t vunder = vdupq_n_u8(static_cast<uint8_t>('_'));
    std::size_t i=0;
    for (; i+16<=n; i+=16) {
      uint8x16_t v = vld1q_u8(reinterpret_cast<const uint8_t*>(src+i));
      uint8x16_t m1 = vceqq_u8(v, vplus);
      uint8x16_t m2 = vceqq_u8(v, vslash);
      v = vbslq_u8(m1, vdash,  v);
      v = vbslq_u8(m2, vunder, v);
      vst1q_u8(reinterpret_cast<uint8_t*>(dst+i), v);
    }
    for (; i<n; ++i) { char c=src[i]; if(c=='+') c='-'; else if(c=='/') c='_'; dst[i]=c; }
  }
  inline void map_url2std_neon(char* dst, const char* src, std::size_t n) {
    const uint8x16_t vdash  = vdupq_n_u8(static_cast<uint8_t>('-'));
    const uint8x16_t vunder = vdupq_n_u8(static_cast<uint8_t>('_'));
    const uint8x16_t vplus  = vdupq_n_u8(static_cast<uint8_t>('+'));
    const uint8x16_t vslash = vdupq_n_u8(static_cast<uint8_t>('/'));
    std::size_t i=0;
    for (; i+16<=n; i+=16) {
      uint8x16_t v = vld1q_u8(reinterpret_cast<const uint8_t*>(src+i));
      uint8x16_t m1 = vceqq_u8(v, vdash);
      uint8x16_t m2 = vceqq_u8(v, vunder);
      v = vbslq_u8(m1, vplus,  v);
      v = vbslq_u8(m2, vslash, v);
      vst1q_u8(reinterpret_cast<uint8_t*>(dst+i), v);
    }
    for (; i<n; ++i) { char c=src[i]; if(c=='-') c='+'; else if(c=='_') c='/'; dst[i]=c; }
  }
  #endif

  // Registry setup (once)
  inline void ensure_map_kernels_registered() {
    using xps::crypto::simd::dispatch::ISA;
    using xps::crypto::simd::dispatch::kernels::register_kernel;

    static bool once = []{
      // Scalar
      register_kernel<map_fn>("b64.map.std2url", ISA::PORTABLE, &map_std2url_scalar, 0);
      register_kernel<map_fn>("b64.map.url2std", ISA::PORTABLE, &map_url2std_scalar, 0);
      // x86
      #if defined(__AVX512BW__)
        register_kernel<map_fn>("b64.map.std2url", ISA::AVX512BW, &map_std2url_avx512, 30);
        register_kernel<map_fn>("b64.map.url2std", ISA::AVX512BW, &map_url2std_avx512, 30);
      #endif
      #if defined(__AVX2__)
        register_kernel<map_fn>("b64.map.std2url", ISA::AVX2, &map_std2url_avx2, 20);
        register_kernel<map_fn>("b64.map.url2std", ISA::AVX2, &map_url2std_avx2, 20);
      #endif
      // ARM
      #if defined(__aarch64__) || defined(__ARM_NEON)
        register_kernel<map_fn>("b64.map.std2url", ISA::NEON64, &map_std2url_neon, 15);
        register_kernel<map_fn>("b64.map.url2std", ISA::NEON64, &map_url2std_neon, 15);
        register_kernel<map_fn>("b64.map.std2url", ISA::NEON,   &map_std2url_neon, 15);
        register_kernel<map_fn>("b64.map.url2std", ISA::NEON,   &map_url2std_neon, 15);
      #endif
      return true;
    }();
    (void)once;
  }

  inline map_fn resolve_map_kernel(std::string_view op, map_fn fallback) {
    ensure_map_kernels_registered();
    using xps::crypto::simd::dispatch::kernels::resolve_kernel;
    if (auto fn = resolve_kernel<map_fn>(op, nullptr)) return fn;
    return fallback;
  }

} // namespace xps::intx::detail


namespace xps::intx::detail {

// ======== Ultra-fast scalar helpers (48->64 mega-unroll, then 12->16) ========
// - Large inputs: process 48 bytes per iteration (16 groups × 3 bytes -> 64 chars)
// - Small inputs (≤32B): minimal-overhead loop to reduce per-iteration cost
inline std::size_t encode_fast_scalar_unrolled(const std::byte* in,
                                               std::size_t len,
                                               char* out,
                                               const char* alph,
                                               bool pad) noexcept {
  std::size_t i=0, o=0;

  // Endianness-safe 4-byte store
  auto W32 = [&](std::uint32_t v){
    if constexpr (std::endian::native == std::endian::little) {
      xps::crypto::internal::secure_copy(out + o, &v, 4);
    } else {
      out[o + 0] = static_cast<char>( (v >>  0) & 0xFF );
      out[o + 1] = static_cast<char>( (v >>  8) & 0xFF );
      out[o + 2] = static_cast<char>( (v >> 16) & 0xFF );
      out[o + 3] = static_cast<char>( (v >> 24) & 0xFF );
    }
    o += 4;
  };

  // Tiny path (≤32B)
  if (len <= 32) {
    while (i + 3 <= len) {
      const unsigned a = std::to_integer<unsigned char>(in[i+0]);
      const unsigned b = std::to_integer<unsigned char>(in[i+1]);
      const unsigned c = std::to_integer<unsigned char>(in[i+2]);
      const unsigned v = (a<<16) | (b<<8) | c;
      const std::uint32_t outv =
        (std::uint32_t)alph[(v>>18)&0x3F]        |
        (std::uint32_t)alph[(v>>12)&0x3F] << 8   |
        (std::uint32_t)alph[(v>> 6)&0x3F] << 16  |
        (std::uint32_t)alph[(v>> 0)&0x3F] << 24;
      W32(outv);
      i += 3;
    }
    goto TAIL;
  }

  // Mega-unroll: 48B -> 64 chars per outer iteration
  while (i + 48 <= len) {
    #pragma GCC unroll 16
    for (int g=0; g<16; ++g) {
      const unsigned a0 = std::to_integer<unsigned char>(in[i + 3*g + 0]);
      const unsigned a1 = std::to_integer<unsigned char>(in[i + 3*g + 1]);
      const unsigned a2 = std::to_integer<unsigned char>(in[i + 3*g + 2]);
      const unsigned v  = (a0<<16) | (a1<<8) | a2;
      const std::uint32_t outv =
        (std::uint32_t)alph[(v>>18)&0x3F]        |
        (std::uint32_t)alph[(v>>12)&0x3F] << 8   |
        (std::uint32_t)alph[(v>> 6)&0x3F] << 16  |
        (std::uint32_t)alph[(v>> 0)&0x3F] << 24;
      W32(outv);
    }
    i += 48;

    // Optional prefetch to reduce cache misses
    #if defined(__GNUG__)
      __builtin_prefetch(in + i + 256, 0, 1);
    #endif
  }

  // Secondary unroll: 12B -> 16 chars
  while (i + 12 <= len) {
    const unsigned a0 = std::to_integer<unsigned char>(in[i+0]);
    const unsigned a1 = std::to_integer<unsigned char>(in[i+1]);
    const unsigned a2 = std::to_integer<unsigned char>(in[i+2]);
    const unsigned a3 = std::to_integer<unsigned char>(in[i+3]);
    const unsigned a4 = std::to_integer<unsigned char>(in[i+4]);
    const unsigned a5 = std::to_integer<unsigned char>(in[i+5]);
    const unsigned a6 = std::to_integer<unsigned char>(in[i+6]);
    const unsigned a7 = std::to_integer<unsigned char>(in[i+7]);
    const unsigned a8 = std::to_integer<unsigned char>(in[i+8]);
    const unsigned a9 = std::to_integer<unsigned char>(in[i+9]);
    const unsigned aa = std::to_integer<unsigned char>(in[i+10]);
    const unsigned ab = std::to_integer<unsigned char>(in[i+11]);

    const unsigned v0 = (a0<<16) | (a1<<8) | a2;
    const unsigned v1 = (a3<<16) | (a4<<8) | a5;
    const unsigned v2 = (a6<<16) | (a7<<8) | a8;
    const unsigned v3 = (a9<<16) | (aa<<8) | ab;

    const std::uint32_t out0 =
      (std::uint32_t)alph[(v0>>18)&0x3F]        |
      (std::uint32_t)alph[(v0>>12)&0x3F] << 8   |
      (std::uint32_t)alph[(v0>> 6)&0x3F] << 16  |
      (std::uint32_t)alph[(v0>> 0)&0x3F] << 24;
    const std::uint32_t out1 =
      (std::uint32_t)alph[(v1>>18)&0x3F]        |
      (std::uint32_t)alph[(v1>>12)&0x3F] << 8   |
      (std::uint32_t)alph[(v1>> 6)&0x3F] << 16  |
      (std::uint32_t)alph[(v1>> 0)&0x3F] << 24;
    const std::uint32_t out2 =
      (std::uint32_t)alph[(v2>>18)&0x3F]        |
      (std::uint32_t)alph[(v2>>12)&0x3F] << 8   |
      (std::uint32_t)alph[(v2>> 6)&0x3F] << 16  |
      (std::uint32_t)alph[(v2>> 0)&0x3F] << 24;
    const std::uint32_t out3 =
      (std::uint32_t)alph[(v3>>18)&0x3F]        |
      (std::uint32_t)alph[(v3>>12)&0x3F] << 8   |
      (std::uint32_t)alph[(v3>> 6)&0x3F] << 16  |
      (std::uint32_t)alph[(v3>> 0)&0x3F] << 24;

    W32(out0); W32(out1); W32(out2); W32(out3);
    i += 12;
  }

TAIL:
  // tail (0..11)
  while (i + 3 <= len) {
    const unsigned a = std::to_integer<unsigned char>(in[i+0]);
    const unsigned b = std::to_integer<unsigned char>(in[i+1]);
    const unsigned c = std::to_integer<unsigned char>(in[i+2]);
    const unsigned v = (a<<16) | (b<<8) | c;
    const std::uint32_t outv =
      (std::uint32_t)alph[(v>>18)&0x3F]        |
      (std::uint32_t)alph[(v>>12)&0x3F] << 8   |
      (std::uint32_t)alph[(v>> 6)&0x3F] << 16  |
      (std::uint32_t)alph[(v>> 0)&0x3F] << 24;
    W32(outv);
    i += 3;
  }

  const std::size_t rem = len - i;
  if (rem == 1) {
    const unsigned a = std::to_integer<unsigned char>(in[i]);
    const unsigned v = (a<<16);
    out[o++] = alph[(v>>18)&0x3F];
    out[o++] = alph[(v>>12)&0x3F];
    if (pad) { out[o++] = '='; out[o++] = '='; }
  } else if (rem == 2) {
    const unsigned a = std::to_integer<unsigned char>(in[i+0]);
    const unsigned b = std::to_integer<unsigned char>(in[i+1]);
    const unsigned v = (a<<16) | (b<<8);
    out[o++] = alph[(v>>18)&0x3F];
    out[o++] = alph[(v>>12)&0x3F];
    out[o++] = alph[(v>> 6)&0x3F];
    if (pad) out[o++] = '=';
  }

  return o;
}

// Fast decode without whitespace, supports unpadded tail (rem 2 or 3).
// Accepts '=' optionally at the very end even if require_padding==false.
inline std::size_t decode_fast_scalar_nows(std::string_view s,
                                           std::byte* out,
                                           bool require_padding,
                                           bool url_relaxed) {
  const unsigned char* t = DEC_STD.t; // 0..63 or 0x80 invalid
  std::size_t i=0, o=0, n=s.size();
  auto W24 = [&](std::uint32_t v, int bytes){
    if (bytes>=1) out[o++] = std::byte((v>>16)&0xFF);
    if (bytes>=2) out[o++] = std::byte((v>> 8)&0xFF);
    if (bytes>=3) out[o++] = std::byte((v>> 0)&0xFF);
  };

  // Full quads
  while (i + 4 <= n) {
    unsigned char c0 = (unsigned char)s[i+0];
    unsigned char c1 = (unsigned char)s[i+1];
    unsigned char c2 = (unsigned char)s[i+2];
    unsigned char c3 = (unsigned char)s[i+3];

    // strict Standard unless url_relaxed=true
    if (!url_relaxed) {
      if (c0=='-'||c0=='_'||c1=='-'||c1=='_'||c2=='-'||c2=='_'||c3=='-'||c3=='_')
        return 0; // invalid mixing
    } else {
      if (c0=='-') c0 = '+'; if (c0=='_') c0 = '/';
      if (c1=='-') c1 = '+'; if (c1=='_') c1 = '/';
      if (c2=='-') c2 = '+'; if (c2=='_') c2 = '/';
      if (c3=='-') c3 = '+'; if (c3=='_') c3 = '/';
    }

    unsigned d0 = t[c0], d1 = t[c1], d2, d3;

    // '=' handling: accept optionally at the very end
    if (c2=='=') {
      d2 = 0; d3 = 0;
      if (d0==0x80 || d1==0x80) return 0;
      const std::uint32_t v = (std::uint32_t(d0)<<18) | (std::uint32_t(d1)<<12);
      W24(v,1);
      if (i+4 != n) return 0;
      return o;
    }
    d2 = t[c2]; if (d2==0x80) return 0;

    if (c3=='=') {
      d3 = 0;
      if (d0==0x80 || d1==0x80 || d2==0x80) return 0;
      const std::uint32_t v = (std::uint32_t(d0)<<18) | (std::uint32_t(d1)<<12) | (std::uint32_t(d2)<<6);
      W24(v,2);
      if (i+4 != n) return 0;
      return o;
    }

    d3 = t[c3];
    if (d0==0x80 || d1==0x80 || d3==0x80) return 0;

    const std::uint32_t v = (std::uint32_t(d0)<<18) | (std::uint32_t(d1)<<12) | (std::uint32_t(d2)<<6) | std::uint32_t(d3);
    W24(v,3);
    i += 4;
  }

  // Unpadded tail (require_padding==false): allow rem == 2 or 3
  const std::size_t rem = n - i;
  if (rem == 0) return o;

  if (require_padding) return 0; // leftover illegal if padding required

  if (rem == 2) {
    unsigned char c0 = (unsigned char)s[i+0];
    unsigned char c1 = (unsigned char)s[i+1];
    if (!url_relaxed) {
      if (c0=='-'||c0=='_'||c1=='-'||c1=='_') return 0;
    } else {
      if (c0=='-') c0='+'; if (c0=='_') c0='/';
      if (c1=='-') c1='+'; if (c1=='_') c1='/';
    }
    if (c0=='=' || c1=='=') return 0;
    unsigned d0 = t[c0], d1 = t[c1];
    if (d0==0x80 || d1==0x80) return 0;
    const std::uint32_t v = (std::uint32_t(d0)<<18) | (std::uint32_t(d1)<<12);
    W24(v,1);
    return o;
  }

  if (rem == 3) {
    unsigned char c0 = (unsigned char)s[i+0];
    unsigned char c1 = (unsigned char)s[i+1];
    unsigned char c2 = (unsigned char)s[i+2];
    if (!url_relaxed) {
      if (c0=='-'||c0=='_'||c1=='-'||c1=='_'||c2=='-'||c2=='_') return 0;
    } else {
      if (c0=='-') c0='+'; if (c0=='_') c0='/';
      if (c1=='-') c1='+'; if (c1=='_') c1='/';
      if (c2=='-') c2='+'; if (c2=='_') c2='/';
    }
    if (c0=='=' || c1=='=' || c2=='=') return 0;
    unsigned d0 = t[c0], d1 = t[c1], d2 = t[c2];
    if (d0==0x80 || d1==0x80 || d2==0x80) return 0;
    const std::uint32_t v = (std::uint32_t(d0)<<18) | (std::uint32_t(d1)<<12) | (std::uint32_t(d2)<<6);
    out[o++] = std::byte((v>>16)&0xFF);
    out[o++] = std::byte((v>> 8)&0xFF);
    return o;
  }

  // rem == 1 → dangling sextet (invalid)
  return 0;
}

inline void wrap_b64(std::string& out, std::string_view raw, std::size_t line_len, bool crlf) {
  if (line_len == 0 || raw.empty()) { out.assign(raw.data(), raw.size()); return; }
  const std::size_t n = raw.size();
  const std::size_t bl = crlf ? 2 : 1;
  const std::size_t lines = (n + line_len - 1) / line_len;
  const std::size_t extra = (lines>1) ? (lines - 1) * bl : 0;
  out.resize(n + extra);
  std::size_t rpos=0, wpos=0, rem=n;
  while (rem) {
    const std::size_t chunk = (rem > line_len) ? line_len : rem;
    xps::crypto::internal::secure_copy(&out[wpos], raw.data()+rpos, chunk);
    rpos += chunk; wpos += chunk; rem -= chunk;
    if (rem) {
      if (crlf) { out[wpos++] = '\r'; out[wpos++] = '\n'; }
      else      { out[wpos++] = '\n'; }
    }
  }
}

} // namespace xps::intx::detail

// ------------------------------- Public API (export) -------------------------
export namespace xps::intx {

  using Bytes     = std::vector<std::byte>;
  template<class T>
  using Result    = xps::expected<T, std::string>;
  using BytesView = std::span<const std::byte>;

  enum class Variant : std::uint8_t { Standard = 0, Url = 1 };

  struct EncodeOptions {
    Variant     variant  { Variant::Standard };
    bool        pad      { true };
    std::size_t line_len { 0 };     // 0 = no wrapping
    bool        use_crlf { false };  // if wrapping: true → "\r\n", false → "\n"
  };
  struct DecodeOptions {
    Variant variant            { Variant::Standard };
    bool    accept_whitespace  { true };
    bool    require_padding    { false };
    bool    url_relaxed        { false };  // strict by default
  };

  // ---------------------------------------------------------------------------
  // Encode (one-shot)
  // ---------------------------------------------------------------------------
  [[nodiscard]] inline std::size_t
  encoded_length(std::size_t input_len, const EncodeOptions& opt = {}) noexcept {
    const auto base = detail::enc_len_no_wrap(input_len, opt.pad);
    return base + detail::lines_extra(base, opt.line_len, opt.use_crlf);
  }

  [[nodiscard]] inline Result<std::string>
  encode(BytesView src, const EncodeOptions& opt = {}) {
    const char* alph = detail::alphabet(opt.variant == Variant::Standard);

    const std::size_t base_len = detail::enc_len_no_wrap(src.size(), opt.pad);
    std::string raw; raw.resize(base_len);

    const std::size_t written =
        detail::encode_fast_scalar_unrolled(src.data(), src.size(),
                                            raw.data(), alph, opt.pad);
    raw.resize(written);

    if (opt.line_len == 0) {
      return raw;
    } else {
      std::string wrapped;
      detail::wrap_b64(wrapped, std::string_view{raw}, opt.line_len, opt.use_crlf);
      return wrapped;
    }
  }

  [[nodiscard]] inline Result<std::string>
  encode(std::string_view s, const EncodeOptions& opt = {}) {
    return encode(BytesView{ reinterpret_cast<const std::byte*>(s.data()), s.size() }, opt);
  }

  // ---------------------------------------------------------------------------
  // Decode (one-shot)
  // ---------------------------------------------------------------------------
  [[nodiscard]] inline std::size_t
  decoded_maxlen(std::string_view s) noexcept {
    std::size_t useful=0;
    for (unsigned char c : s) if (!detail::is_space(c)) useful++;
    if (useful==0) return 0;
    const std::size_t quads = useful/4 + (useful%4 ? 1 : 0);
    return quads * 3;
  }

  [[nodiscard]] inline Result<Bytes>
  decode(std::string_view s, const DecodeOptions& opt = {}) {

    // Early, explicit error if whitespace is not allowed
    if (!opt.accept_whitespace && detail::has_space(s)) {
      return xps::unexpected<std::string>("[Invalid] whitespace");
    }

    // URL variant
    if (opt.variant == Variant::Url) {
      if (!opt.url_relaxed) {
        bool has_marker=false;
        for (unsigned char c : s) {
          if (c=='+' || c=='/') return xps::unexpected<std::string>("[Invalid] URL variant forbids '+'/'/'");
          if (c=='-' || c=='_') has_marker=true;
        }
        if (!s.empty() && !has_marker)
          return xps::unexpected<std::string>("[Invalid] URL strict requires '-' or '_' marker");
      }
      // Map URL→Standard alphabet, then decode via Standard path
      using detail::map_fn;
      auto map = detail::resolve_map_kernel("b64.map.url2std", &detail::map_url2std_scalar);
      std::string mapped; mapped.resize(s.size());
      map(mapped.data(), s.data(), s.size());
      DecodeOptions std_opt = opt; std_opt.variant = Variant::Standard;
      return decode(std::string_view{mapped}, std_opt);
    }

    // Fast path: no whitespace (or not accepted)
    if (!opt.accept_whitespace || !detail::has_space(s)) {
      Bytes out; out.resize(decoded_maxlen(s));
      std::size_t w = detail::decode_fast_scalar_nows(s, out.data(), opt.require_padding, opt.url_relaxed);
      if (w == 0 && !s.empty()) {
        return xps::unexpected<std::string>("[Invalid] fast path rejected input");
      }
      out.resize(w);
      return out;
    }

    // Fallback validator (accepts whitespace if allowed)
    const auto& DT1 = detail::DEC_STD;
    const unsigned char* t1 = DT1.t;

    Bytes out; out.reserve(decoded_maxlen(s));
    std::uint32_t acc=0; int bits=0; bool seen_pad=false; int pad_count=0;

    auto push_byte = [&](unsigned v){ out.push_back(std::byte(static_cast<unsigned char>(v))); };

    for (unsigned char c : s) {
      if (detail::is_space(c)) {
        if (opt.accept_whitespace) continue;
        return xps::unexpected<std::string>("[Invalid] whitespace in input");
      }

      unsigned char d = t1[c];
      if (d==0x80) { // invalid for Standard
        if (opt.url_relaxed) {
          if (c=='-') d = t1[static_cast<unsigned char>('+')];
          else if (c=='_') d = t1[static_cast<unsigned char>('/')];
          else return xps::unexpected<std::string>("[Invalid] char");
        } else {
          return xps::unexpected<std::string>("[Invalid] char");
        }
      }

      if (c=='=') {
        seen_pad = true;
        pad_count++;
        continue;
      }

      if (seen_pad) return xps::unexpected<std::string>("[Invalid] data after '='");

      acc = (acc<<6) | d;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        push_byte((acc >> bits) & 0xFF);
      }
    }

    if (pad_count > 0 || opt.require_padding) {
      if (opt.require_padding) {
        if (pad_count==0) return xps::unexpected<std::string>("[Invalid] padding required");
      }
      if (pad_count > 2) return xps::unexpected<std::string>("[Invalid] too much padding");
      if ((bits != 0) && (pad_count==0)) return xps::unexpected<std::string>("[Invalid] leftover bits w/o padding");
      if (pad_count > 0) {
        const int eb = (pad_count==1?2:(pad_count==2?4:0));
        if (bits != eb) return xps::unexpected<std::string>("[Invalid] inconsistent padding");
      }
    }

    if (pad_count == 0) {
      if (bits == 6) {
        return xps::unexpected<std::string>("[Invalid] dangling Base64 sextet (length % 4 == 1)");
      }
      // bits ∈ {0,2,4} are fine
    }

    return out;
  }

  [[nodiscard]] inline Result<Bytes>
  decode(const char* s, const DecodeOptions& opt = {}) {
    return decode(std::string_view{s ? s : "", s ? std::strlen(s) : 0}, opt);
  }

  // ---------------------------------------------------------------------------
  // Streaming encoder/decoder
  // ---------------------------------------------------------------------------
  class Encoder {
  public:
    explicit Encoder(EncodeOptions opt = {}) : _opt(opt) {}

    void feed(BytesView chunk, std::string& out) {
      const char* alph = detail::alphabet(_opt.variant == Variant::Standard);
      const std::byte* p = chunk.data();
      std::size_t n = chunk.size();

      auto newline = [&](std::string& o){
        if (_opt.line_len==0) return;
        if (_opt.use_crlf) { o.push_back('\r'); o.push_back('\n'); }
        else               { o.push_back('\n'); }
        _col = 0;
      };
      auto need_break = [&](std::string& o, std::size_t need){
        if (_opt.line_len==0) return;
        if (_col + need > _opt.line_len) newline(o);
      };

      // Complete leftover from previous call
      if (_rem > 0) {
        while (_rem < 3 && n > 0) { _tail[_rem++] = *p++; --n; }
        if (_rem == 3) {
          need_break(out, 4);
          const unsigned a = static_cast<unsigned>(std::to_integer<unsigned char>(_tail[0]));
          const unsigned b = static_cast<unsigned>(std::to_integer<unsigned char>(_tail[1]));
          const unsigned c = static_cast<unsigned>(std::to_integer<unsigned char>(_tail[2]));
          const unsigned v = (a<<16) | (b<<8) | c;
          out.push_back(alph[(v>>18)&0x3F]);
          out.push_back(alph[(v>>12)&0x3F]);
          out.push_back(alph[(v>> 6)&0x3F]);
          out.push_back(alph[(v>> 0)&0x3F]);
          _col += 4;
          _rem = 0;
        }
      }

      // Full groups
      while (n >= 3) {
        need_break(out, 4);
        const unsigned a = static_cast<unsigned>(std::to_integer<unsigned char>(p[0]));
        const unsigned b = static_cast<unsigned>(std::to_integer<unsigned char>(p[1]));
        const unsigned c = static_cast<unsigned>(std::to_integer<unsigned char>(p[2]));
        const unsigned v = (a<<16) | (b<<8) | c;
        out.push_back(alph[(v>>18)&0x3F]);
        out.push_back(alph[(v>>12)&0x3F]);
        out.push_back(alph[(v>> 6)&0x3F]);
        out.push_back(alph[(v>> 0)&0x3F]);
        p += 3; n -= 3; _col += 4;
      }

      // Save remainder (0..2)
      while (n > 0) { _tail[_rem++] = *p++; --n; }
    }

    void finalize(std::string& out) {
      const char* alph = detail::alphabet(_opt.variant == Variant::Standard);

      auto newline = [&](std::string& o){
        if (_opt.line_len==0) return;
        if (_opt.use_crlf) { o.push_back('\r'); o.push_back('\n'); }
        else               { o.push_back('\n'); }
        _col = 0;
      };
      auto need_break = [&](std::string& o, std::size_t need){
        if (_opt.line_len==0) return;
        if (_col + need > _opt.line_len) newline(o);
      };

      if (_rem == 1) {
        const unsigned a = static_cast<unsigned>(std::to_integer<unsigned char>(_tail[0]));
        const unsigned v = (a << 16);
        const std::size_t need = _opt.pad ? 4 : 2;
        need_break(out, need);
        out.push_back(alph[(v>>18)&0x3F]); ++_col;
        out.push_back(alph[(v>>12)&0x3F]); ++_col;
        if (_opt.pad) { out.push_back('='); out.push_back('='); _col += 2; }
      } else if (_rem == 2) {
        const unsigned a = static_cast<unsigned>(std::to_integer<unsigned char>(_tail[0]));
        const unsigned b = static_cast<unsigned>(std::to_integer<unsigned char>(_tail[1]));
        const unsigned v = (a << 16) | (b << 8);
        const std::size_t need = _opt.pad ? 4 : 3;
        need_break(out, need);
        out.push_back(alph[(v>>18)&0x3F]); ++_col;
        out.push_back(alph[(v>>12)&0x3F]); ++_col;
        out.push_back(alph[(v>> 6)&0x3F]); ++_col;
        if (_opt.pad) { out.push_back('='); ++_col; }
      }
      _rem = 0;
    }

  private:
    EncodeOptions _opt{};
    std::byte     _tail[3]{}; int _rem{0};
    std::size_t   _col{0};   // line wrapping across calls
  };

  class Decoder {
  public:
    explicit Decoder(DecodeOptions opt = {}) : _opt(opt) {}

    [[nodiscard]] Result<void> feed(std::string_view s, Bytes& out) {
      // STRICT URL: track markers across chunks
      if (_opt.variant == Variant::Url && !_opt.url_relaxed) {
        for (unsigned char c : s) {
          if (c=='+' || c=='/')
            return xps::unexpected<std::string>("[Invalid] URL variant forbids '+'/'/'");
          if (c=='-' || c=='_') _saw_url_marker = true;
        }
        _seen_total += s.size();
      }

      // Map URL→Standard alphabet before core pipeline
      if (_opt.variant == Variant::Url) {
        using detail::map_fn;
        auto map = detail::resolve_map_kernel("b64.map.url2std", &detail::map_url2std_scalar);
        _tmp.resize(s.size());
        map(_tmp.data(), s.data(), s.size());
        s = std::string_view{_tmp};
      }

      const auto& DT = detail::DEC_STD;
      const unsigned char* t = DT.t;

      for (unsigned char c : s) {
        if (detail::is_space(c)) {
          if (_opt.accept_whitespace) continue;
          else return xps::unexpected<std::string>("[Invalid] whitespace");
        }
        unsigned char d = t[c];
        if (d==0x80) return xps::unexpected<std::string>("[Invalid] character");
        if (d==0x40) { _seen_pad=true; _pad_count++; continue; }
        if (_seen_pad) return xps::unexpected<std::string>("[Invalid] data after padding");

        _acc = (_acc<<6) | d; _bits += 6;
        if (_bits>=8) { _bits-=8; out.push_back(std::byte(static_cast<unsigned char>((_acc>>_bits)&0xFF))); }
      }
      return {};
    }

    [[nodiscard]] Result<void> finalize(Bytes& out) {
      (void)out;
      // Complete URL-STRICT check across chunks
      if (_opt.variant == Variant::Url && !_opt.url_relaxed) {
        if (_seen_total > 0 && !_saw_url_marker)
          return xps::unexpected<std::string>("[Invalid] URL strict requires '-' or '_' marker");
      }

      auto expected_bits_for_pad = [](int pc) -> int { return pc==0?0:(pc==1?2:4); };

      if (_opt.require_padding) {
        if (_pad_count == 0) {
          if (_bits != 0) return xps::unexpected<std::string>("[Invalid] missing padding");
        } else {
          const int eb = expected_bits_for_pad(_pad_count);
          if (_bits != eb) return xps::unexpected<std::string>("[Invalid] wrong padding");
        }
      } else {
        if (_pad_count > 0) {
          const int eb = expected_bits_for_pad(_pad_count);
          if (_bits != eb) return xps::unexpected<std::string>("[Invalid] inconsistent padding");
        }
      }

      if (_pad_count == 0) {
        if (_bits == 6) return xps::unexpected<std::string>("[Invalid] dangling Base64 sextet (length % 4 == 1)");
      }

      _bits=0; _acc=0; _seen_pad=false; _pad_count=0; _tmp.clear();
      _seen_total=0; _saw_url_marker=false;
      return {};
    }

  private:
    DecodeOptions  _opt{};
    std::uint32_t  _acc{0};
    int            _bits{0};
    bool           _seen_pad{false};
    int            _pad_count{0};
    std::string    _tmp; // buffer for URL→STD mapping

    // STRICT tracking across chunks
    std::size_t  _seen_total{0};
    bool         _saw_url_marker{false};
  };

  // ---------------------------------------------------------------------------
  // Minimal self-test
  // ---------------------------------------------------------------------------
  [[nodiscard]] inline xps::expected<void, std::string>
  selftest_minimal() {
    struct Vec { const char* plain; const char* std_b64; const char* url_b64; };
    static constexpr Vec V[] = {
      {"", "", ""},
      {"f", "Zg==", "Zg"},
      {"fo", "Zm8=", "Zm8"},
      {"foo", "Zm9v", "Zm9v"},
      {"foob", "Zm9vYg==", "Zm9vYg"},
      {"fooba", "Zm9vYmE=", "Zm9vYmE"},
      {"foobar", "Zm9vYmFy", "Zm9vYmFy"}
    };

    for (auto& v : V) {
      auto e1 = encode(v.plain, EncodeOptions{.variant=Variant::Standard, .pad=true});
      if (!e1) return xps::unexpected<std::string>(e1.error());
      if (*e1 != std::string(v.std_b64)) return xps::unexpected<std::string>("std encode mismatch");
      auto e2 = encode(v.plain, EncodeOptions{.variant=Variant::Url, .pad=false});
      if (!e2) return xps::unexpected<std::string>(e2.error());
      if (*e2 != std::string(v.url_b64)) return xps::unexpected<std::string>("url encode mismatch");

      auto d1 = decode(v.std_b64, DecodeOptions{.variant=Variant::Standard, .require_padding=true});
      if (!d1) return xps::unexpected<std::string>(d1.error());
      if (std::string(reinterpret_cast<const char*>(d1->data()), d1->size()) != std::string(v.plain))
        return xps::unexpected<std::string>("std decode mismatch");

      auto d2 = decode(v.url_b64, DecodeOptions{.variant=Variant::Url, .require_padding=false});
      if (!d2) return xps::unexpected<std::string>(d2.error());
      if (std::string(reinterpret_cast<const char*>(d2->data()), d2->size()) != std::string(v.plain))
        return xps::unexpected<std::string>("url decode mismatch");
    }

    // Optional padding acceptance
    {
      auto d = decode("Zg==", DecodeOptions{.variant=Variant::Standard, .require_padding=false});
      if (!d || std::string(reinterpret_cast<const char*>(d->data()), d->size()) != "f")
        return xps::unexpected<std::string>("optional '=' not accepted (std)");
    }
    {
      auto d = decode("Zg", DecodeOptions{.variant=Variant::Standard, .require_padding=false});
      if (!d || std::string(reinterpret_cast<const char*>(d->data()), d->size()) != "f")
        return xps::unexpected<std::string>("unpadded not accepted (std)");
    }
    // URL strict: must reject '+' '/'
    {
      auto d = decode("Zm9vYmFy", DecodeOptions{.variant=Variant::Url, .url_relaxed=false});
      if (d) return xps::unexpected<std::string>("URL strict didn't reject std alphabet");
    }

    return {};
  }

  // Convenience helper: keeps the classic signature
  inline const char* b64(const char* s) {
    thread_local std::string buf;
    auto r = encode(std::string_view{s ? s : ""}, EncodeOptions{.variant=Variant::Standard, .pad=true});
    buf = r ? *r : std::string{};
    return buf.c_str();
  }

} // namespace xps::intx

export inline const char* b64_impl_tag() noexcept {
  return "B64X_OPT_V7_STRICT_MARKER_DIRECT_URL_ENC_48x64";
}

