module; // ===== Global Module Fragment =====
#include <cstddef>
#include <cstdint>
#include <array>
#include <type_traits>
#include <memory>
#include <utility>
#include <atomic>
#include <span>
#include <string>
#include <string_view>
#include <new>       // std::align_val_t, __STDCPP_DEFAULT_NEW_ALIGNMENT__
#include <limits>
#include <concepts>  // std::unsigned_integral
#include <cstring>   // std::memcpy for non-secret fast paths (optional)

export module xps.crypto.internal.common;

// Imports must immediately follow the module declaration.
import xps.memory; // unified engine: secure_erase, memcpy, memcmp_constant_time

export
namespace xps::crypto::internal {

// ============================================================================
// Policy & guards
// ============================================================================
inline constexpr std::size_t MAX_COMPARE_SIZE   = 1024 * 1024; // 1 MiB
inline constexpr bool        ENABLE_SIZE_GUARDS = true;        // reject pathological sizes

// Portable compiler fence to prevent reordering across sensitive ops
[[gnu::always_inline]] inline void compiler_fence() noexcept {
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

// ============================================================================
// Constant-time equality
// ============================================================================

[[nodiscard]] inline bool ct_equal(const void* a, const void* b, std::size_t n) noexcept {
    if (n == 0) return true;
    if (a == nullptr || b == nullptr) return false;
    if constexpr (ENABLE_SIZE_GUARDS) {
        if (n > MAX_COMPARE_SIZE) return false;
    }
    const bool eq = xps::memory::memcmp_constant_time(a, b, n);
    compiler_fence();
    return eq;
}

template<typename T, std::size_t N>
[[nodiscard]] inline bool ct_equal(const std::array<T, N>& a,
                                   const std::array<T, N>& b) noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable for secure comparison");
    return ct_equal(a.data(), b.data(), N * sizeof(T));
}

template<typename T>
[[nodiscard]] inline bool ct_equal(std::span<const T> a,
                                   std::span<const T> b) noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable for secure comparison");
    if (a.size() != b.size()) return false; // size diff is non-secret
    return ct_equal(a.data(), b.data(), a.size() * sizeof(T));
}

[[nodiscard]] inline bool ct_equal(std::string_view a,
                                   std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    return ct_equal(a.data(), b.data(), a.size());
}

// ============================================================================
// Constant-time zero test
// ============================================================================

[[nodiscard]] inline bool ct_is_zero(const void* p, std::size_t n) noexcept {
    if (n == 0) return true;
    if (p == nullptr) return false;
    if constexpr (ENABLE_SIZE_GUARDS) {
        if (n > MAX_COMPARE_SIZE) return false;
    }
    const auto* q = static_cast<const unsigned char*>(p);
    unsigned char acc = 0;
    for (std::size_t i = 0; i < n; ++i) acc |= q[i];
    compiler_fence();
    return acc == 0;
}

template<typename T, std::size_t N>
[[nodiscard]] inline bool ct_is_zero(const std::array<T, N>& arr) noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable for secure zero check");
    return ct_is_zero(arr.data(), N * sizeof(T));
}

template<typename T>
[[nodiscard]] inline bool ct_is_zero(std::span<const T> s) noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable for secure zero check");
    return ct_is_zero(s.data(), s.size() * sizeof(T));
}

// ============================================================================
// Secure wiping
// ============================================================================

inline void wipe(void* p, std::size_t n) noexcept {
    xps::memory::secure_erase(p, n);
    compiler_fence();
}

template<typename T>
inline void wipe_object(T& obj) noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable for secure wiping");
    wipe(std::addressof(obj), sizeof(T));
}

template<typename T>
inline void wipe_span(std::span<T> s) noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable for secure wiping");
    wipe(s.data(), s.size() * sizeof(T));
}

template<typename CharT, typename Traits, typename Alloc>
inline void wipe_string(std::basic_string<CharT, Traits, Alloc>& s) noexcept {
    if (!s.empty()) {
        wipe(s.data(), s.size() * sizeof(CharT));
        s.clear();
        s.shrink_to_fit();
    }
}

struct scope_wipe {
    void* p{nullptr};
    std::size_t n{0};
    ~scope_wipe() { if (p && n) wipe(p, n); }
};

// ============================================================================
// Secure copy (routes to unified engine)
// ============================================================================

inline void secure_copy(void* dest, const void* src, std::size_t n) noexcept {
    if (!dest || !src || n == 0) return;
    (void)xps::memory::memcpy(dest, src, n);
    compiler_fence();
}

template<typename T>
inline void secure_copy_typed(T* dest, const T* src, std::size_t count) noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable for secure copy");
    if (!dest || !src || count == 0) return;
    (void)xps::memory::memcpy(dest, src, count * sizeof(T));
    compiler_fence();
}

template<typename T>
inline void secure_copy_span(std::span<T> dest, std::span<const T> src) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable for secure copy");
    if (src.size() > dest.size()) {
        throw std::runtime_error("secure_copy_span: destination too small");
    }
    secure_copy_typed(dest.data(), src.data(), src.size());
}

// ============================================================================
// Overlap helper (overflow-safe)
// ============================================================================

[[nodiscard]] inline bool memory_non_overlapping(const void* a, std::size_t a_size,
                                                 const void* b, std::size_t b_size) noexcept {
    if (!a || !b) return true;
    const auto A = static_cast<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(a));
    const auto B = static_cast<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(b));
    auto safe_end = [](std::uintptr_t base, std::size_t len) noexcept {
        constexpr auto UMAX = std::numeric_limits<std::uintptr_t>::max();
        std::uintptr_t end = base + static_cast<std::uintptr_t>(len);
        if (end < base) end = UMAX; // saturate on overflow
        return end;
    };
    const std::uintptr_t Aend = safe_end(A, a_size);
    const std::uintptr_t Bend = safe_end(B, b_size);
    return (Aend <= B) || (Bend <= A);
}

// ============================================================================
// Constant-time primitives (base)
// ============================================================================

// Returns an all-ones mask of unsigned type U if cond==true, else 0.
template <class U>
[[nodiscard]] inline std::enable_if_t<std::is_unsigned_v<U>, U>
ct_mask(bool cond) noexcept {
    return static_cast<U>(0) - static_cast<U>(cond);
}

// Select between a and b using an all-ones mask (U) without branches:
// result = (a & ~mask) ^ (b & mask)
template <class T, class U>
[[nodiscard]] inline T ct_select_masked(T a, T b, U mask) noexcept {
    static_assert(std::is_unsigned_v<U>, "Mask type must be unsigned");
    using W = std::make_unsigned_t<T>;
    const W wa = static_cast<W>(a);
    const W wb = static_cast<W>(b);
    const W wm = static_cast<W>(mask);
    const W r  = (wa & ~wm) ^ (wb & wm);
    return static_cast<T>(r);
}

// Select between a and b based on boolean condition in constant time.
template <class T>
[[nodiscard]] inline T ct_select(T a, T b, bool cond) noexcept {
    using U = std::make_unsigned_t<T>;
    return ct_select_masked<T,U>(a, b, ct_mask<U>(cond));
}

// In-place XOR: dst[i] ^= src[i] for n bytes (constant-time loop).
inline void ct_memxor_inplace(void* dst, const void* src, std::size_t n) noexcept {
    if (!dst || !src || n == 0) return;
    auto* d = static_cast<unsigned char*>(dst);
    const auto* s = static_cast<const unsigned char*>(src);
    for (std::size_t i = 0; i < n; ++i) d[i] ^= s[i];
    compiler_fence();
}

template <std::unsigned_integral T>
inline void ct_xor_inplace_typed(T* dst, const T* src, std::size_t count) noexcept {
    if (!dst || !src || count == 0) return;
    for (std::size_t i = 0; i < count; ++i) dst[i] ^= src[i];
    compiler_fence();
}

template <typename T>
inline void ct_memxor_inplace(std::span<T> dst, std::span<const T> src) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if (src.size() > dst.size()) {
        throw std::runtime_error("ct_memxor_inplace: destination too small");
    }
    ct_memxor_inplace(dst.data(), src.data(), src.size() * sizeof(T));
}

inline void ct_copy_if_mask(void* dst, const void* src, std::size_t n, unsigned char mask) noexcept {
    if (!dst || !src || n == 0) return;
    auto* d = static_cast<unsigned char*>(dst);
    const auto* s = static_cast<const unsigned char*>(src);
    const unsigned char m = mask;
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char di = d[i];
        const unsigned char si = s[i];
        d[i] = (di & static_cast<unsigned char>(~m)) ^ (si & m);
    }
    compiler_fence();
}

template <typename T>
inline void ct_copy_if_mask(std::span<T> dst, std::span<const T> src, unsigned char byte_mask) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if (src.size() > dst.size()) {
        throw std::runtime_error("ct_copy_if_mask: destination too small");
    }
    ct_copy_if_mask(dst.data(), src.data(), src.size() * sizeof(T), byte_mask);
}

// ============================================================================
// Constant-time block selection (NEW)
// ============================================================================

// Broadcast a single byte mask (0x00 or 0xFF) into a word with all bytes = mask.
template <std::unsigned_integral U>
[[nodiscard]] inline U broadcast_mask_byte(unsigned char m) noexcept {
    U w = static_cast<U>(m);
    U r = 0;
    // fill r with repeated byte m
    for (std::size_t i = 0; i < sizeof(U); ++i) {
        r |= static_cast<U>(w) << (i * 8);
    }
    return r;
}

// Word-wise selection: out[i] = (a[i] & ~mask) ^ (b[i] & mask).
// Safe when out==a or out==b; undefined for other overlaps.
template <std::unsigned_integral U>
inline void ct_select_words_typed(U* out, const U* a, const U* b,
                                  std::size_t count, unsigned char byte_mask) noexcept {
    if (!out || !a || !b || count == 0) return;
    const U mw = broadcast_mask_byte<U>(byte_mask);
    for (std::size_t i = 0; i < count; ++i) {
        const U ai = a[i];
        const U bi = b[i];
        out[i] = (ai & ~mw) ^ (bi & mw);
    }
    compiler_fence();
}

// Byte path (alignment-agnostic)
inline void ct_select_bytes(void* out, const void* a, const void* b,
                            std::size_t n, unsigned char byte_mask) noexcept {
    if (!out || !a || !b || n == 0) return;
    auto* d = static_cast<unsigned char*>(out);
    const auto* A = static_cast<const unsigned char*>(a);
    const auto* B = static_cast<const unsigned char*>(b);
    const unsigned char m = byte_mask;
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char ai = A[i];
        const unsigned char bi = B[i];
        d[i] = (ai & static_cast<unsigned char>(~m)) ^ (bi & m);
    }
    compiler_fence();
}

// Bool overload -> mask 0x00/0xFF
inline void ct_select_bytes(void* out, const void* a, const void* b,
                            std::size_t n, bool cond) noexcept {
    const unsigned char m = static_cast<unsigned char>(0) - static_cast<unsigned char>(cond);
    ct_select_bytes(out, a, b, n, m);
}

// Hybrid fast path: word-wise if aligned, else byte path.
// Requires out==a or out==b to be overlap-safe.
inline void ct_select_block(void* out, const void* a, const void* b,
                            std::size_t n, bool cond) noexcept {
    if (!out || !a || !b || n == 0) return;
    const auto up_out = reinterpret_cast<std::uintptr_t>(out);
    const auto up_a   = reinterpret_cast<std::uintptr_t>(a);
    const auto up_b   = reinterpret_cast<std::uintptr_t>(b);

    // Try size_t path if all aligned equally
    constexpr std::size_t W = sizeof(std::size_t);
    const bool aligned = ((up_out | up_a | up_b) % W) == 0;
    const unsigned char m = static_cast<unsigned char>(0) - static_cast<unsigned char>(cond);

    if (aligned) {
        auto*       dout = reinterpret_cast<std::size_t*>(out);
        const auto* Ain  = reinterpret_cast<const std::size_t*>(a);
        const auto* Bin  = reinterpret_cast<const std::size_t*>(b);
        const std::size_t words = n / W;
        const std::size_t tail  = n % W;
        ct_select_words_typed<std::size_t>(dout, Ain, Bin, words, m);
        if (tail) {
            auto*       d2 = reinterpret_cast<unsigned char*>(dout + words);
            const auto* A2 = reinterpret_cast<const unsigned char*>(Ain + words);
            const auto* B2 = reinterpret_cast<const unsigned char*>(Bin + words);
            ct_select_bytes(d2, A2, B2, tail, m);
        }
        compiler_fence();
    } else {
        ct_select_bytes(out, a, b, n, m);
    }
}

// Spans (sizes must be equal). Out may alias a أو b بالكامل.
template <typename T>
inline void ct_select_block(std::span<T> out,
                            std::span<const T> a,
                            std::span<const T> b,
                            bool cond) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if (a.size() != b.size() || out.size() < a.size()) {
        throw std::runtime_error("ct_select_block: size mismatch");
    }
    ct_select_block(out.data(), a.data(), b.data(), a.size() * sizeof(T), cond);
}

// std::array overloads
template <typename T, std::size_t N>
inline void ct_select_block(std::array<T, N>& out,
                            const std::array<T, N>& a,
                            const std::array<T, N>& b,
                            bool cond) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    ct_select_block(out.data(), a.data(), b.data(), N * sizeof(T), cond);
}

// ============================================================================
// Constant-time swap of whole blocks (NEW)
// ============================================================================

// XOR-swap masked: t = (a ^ b) & mask; a ^= t; b ^= t;
// Safe when buffers do not partially overlap (they may be the same size and disjoint).
inline void ct_swap_if(void* a, void* b, std::size_t n, bool cond) noexcept {
    if (!a || !b || n == 0) return;
    auto* A = static_cast<unsigned char*>(a);
    auto* B = static_cast<unsigned char*>(b);
    const unsigned char m = static_cast<unsigned char>(0) - static_cast<unsigned char>(cond);
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char t = static_cast<unsigned char>((A[i] ^ B[i]) & m);
        A[i] = static_cast<unsigned char>(A[i] ^ t);
        B[i] = static_cast<unsigned char>(B[i] ^ t);
    }
    compiler_fence();
}

template <typename T>
inline void ct_swap_if(std::span<T> a, std::span<T> b, bool cond) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    if (a.size() != b.size()) {
        throw std::runtime_error("ct_swap_if: size mismatch");
    }
    ct_swap_if(a.data(), b.data(), a.size() * sizeof(T), cond);
}

template <typename T, std::size_t N>
inline void ct_swap_if(std::array<T, N>& a, std::array<T, N>& b, bool cond) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
    ct_swap_if(a.data(), b.data(), N * sizeof(T), cond);
}

} // namespace xps::crypto::internal

