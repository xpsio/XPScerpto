module; // ──────────────────────────────────────────────────────────────
// Global module fragment
// ──────────────────────────────────────────────────────────────
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

export module xps.crypto.base64x.hybrid_bridge;

import xps.base64x;
import xps.crypto.internal.common;
import xps.crypto.simd.hybrid;
import xps.crypto.simd.dispatch.types;
import xps.crypto.simd.dispatch.kernels;

// ──────────────────────────────────────────────────────────────
// Kernel ABI (void* ctx passed via dst per-op contract)
// ──────────────────────────────────────────────────────────────
export namespace xps::crypto::base64x::bridge {

  struct B64XKernelCtx {
    // Input (encode: raw bytes; decode: base64 text)
    const void* in{nullptr};
    std::size_t in_size{0};

    // Output buffer (optional for size-query first pass)
    void*       out{nullptr};
    std::size_t out_capacity{0};
    std::size_t* out_size{nullptr};

    // Options
    bool url{false};
    bool pad{true};
    bool strict{true};

    // Result status: 0=ok, >0=needs bigger buffer, <0=error
    int status{0};

    // Optional error message buffer
    char* err_buf{nullptr};
    std::size_t err_cap{0};
  };

  inline void set_error(B64XKernelCtx& k, std::string_view msg, int code=-1) {
    k.status = code;
    if (k.err_buf && k.err_cap) {
      const std::size_t n = msg.size() < k.err_cap-1 ? msg.size() : k.err_cap-1;
      xps::crypto::internal::secure_copy(k.err_buf, msg.data(), n);
      k.err_buf[n] = '\0';
    }
  }

  // ---- Encode kernel (FnPtr signature): fn(dst=ctx, src, n) ----
  extern "C" void b64x_encode_kernel(void* dst, const void*, std::size_t) {
    auto& k = *reinterpret_cast<B64XKernelCtx*>(dst);

    xps::b64x::Options opt{};
    opt.profile = k.url ? xps::b64x::ProfileId::Url : xps::b64x::ProfileId::Standard;
    opt.pad     = k.pad;

    xps::b64x::BytesView in{ reinterpret_cast<const std::byte*>(k.in), k.in_size };
    auto r = xps::b64x::encode(in, opt);
    if (!r) { set_error(k, r.error(), -1); return; }

    const std::string& s = *r;
    if (!k.out || !k.out_size) { if (k.out_size) *k.out_size = s.size(); k.status = 1; return; }
    if (k.out_capacity < s.size()) { *k.out_size = s.size(); k.status = 1; return; }
    xps::crypto::internal::secure_copy(k.out, s.data(), s.size());
    *k.out_size = s.size();
    k.status = 0;
  }

  // ---- Decode kernel (FnPtr signature): fn(dst=ctx, src, n) ----
  extern "C" void b64x_decode_kernel(void* dst, const void*, std::size_t) {
    auto& k = *reinterpret_cast<B64XKernelCtx*>(dst);
    auto sv = std::string_view(static_cast<const char*>(k.in), k.in_size);

    xps::b64x::Options opt{};
    opt.profile = k.url ? xps::b64x::ProfileId::Url : xps::b64x::ProfileId::Standard;
    opt.pad     = k.pad;
    opt.ignore_whitespace = !k.strict;
    opt.url_relaxed       = !k.strict;

    auto r = xps::b64x::decode(sv, opt);
    if (!r) { set_error(k, r.error(), -1); return; }

    const auto& v = *r;
    if (!k.out || !k.out_size) { if (k.out_size) *k.out_size = v.size(); k.status = 1; return; }
    if (k.out_capacity < v.size()) { *k.out_size = v.size(); k.status = 1; return; }
    xps::crypto::internal::secure_copy(k.out, v.data(), v.size());
    *k.out_size = v.size();
    k.status = 0;
  }

  // ---- AVX2 decode registration target (same body; runtime fastpaths inside base64x) ----
  extern "C" void b64x_decode_avx2_kernel(void* dst, const void* src, std::size_t n) {
    b64x_decode_kernel(dst, src, n);
  }

} // namespace xps::crypto::base64x::bridge

// ──────────────────────────────────────────────────────────────
// Registry glue
// ──────────────────────────────────────────────────────────────
export namespace xps::crypto::base64x::hybrid_bridge {

  using xps::crypto::simd::hybrid::ImplDesc;
  using xps::crypto::simd::hybrid::register_impl;
  using xps::crypto::simd::hybrid::ISA;
  using xps::crypto::simd::hybrid::FnPtr;
  using xps::crypto::simd::hybrid::SB_SMALL;
  using xps::crypto::simd::hybrid::SB_MED;
  using xps::crypto::simd::hybrid::SB_LARGE;
  using xps::crypto::simd::hybrid::SB_ALL;

  inline void register_all_b64x() {
    using namespace xps::crypto::base64x::bridge;

    register_impl(ImplDesc{ "b64x.encode", ISA::PORTABLE,
                            reinterpret_cast<FnPtr>(&b64x_encode_kernel),
                            /*weight*/ 5u, /*size_mask*/ SB_SMALL | SB_MED, /*ct*/ false });

    register_impl(ImplDesc{ "b64x.decode", ISA::PORTABLE,
                            reinterpret_cast<FnPtr>(&b64x_decode_kernel),
                            /*weight*/ 5u, /*size_mask*/ SB_ALL, /*ct*/ false });

    register_impl(ImplDesc{ "b64x.decode", ISA::AVX2,
                            reinterpret_cast<FnPtr>(&b64x_decode_avx2_kernel),
                            /*weight*/ 10u, /*size_mask*/ SB_MED | SB_LARGE, /*ct*/ false });
  }

} // namespace xps::crypto::base64x::hybrid_bridge

