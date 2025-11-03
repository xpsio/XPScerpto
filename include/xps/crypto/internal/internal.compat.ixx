module; // =================== Global Module Fragment ====================
#include <cstdint>
#include <cstddef>
#include <climits>
#include <string>
#include <variant>   // std::monostate
#include <utility>
#include <atomic>    // fences for secure_clear

#if defined(_WIN32)
  #define XPS_OS_WINDOWS 1
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <bcrypt.h>
  #include <ntstatus.h>
  #pragma comment(lib, "bcrypt.lib")
#else
  #define XPS_OS_POSIX 1
  #include <unistd.h>
  #include <sys/mman.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <sys/resource.h>   // getrlimit, RLIMIT_MEMLOCK
  #if defined(__linux__)
    #include <sys/random.h>   // getrandom()
  #elif defined(__APPLE__)
    #include <CommonCrypto/CommonRandom.h> // CCRandomGenerateBytes
  #endif
#endif
// ======================================================================

export module xps.crypto.internal.compat;

// Import the error/types modules *before* any use of their symbols.
import xps.crypto.types;   // ErrorCode, ErrorSeverity, ErrorCategory, ...
import xps.crypto.errors;  // CryptoError, ResultEx, MakeError, Ok/Err

// ======================================================================
// Non-exported implementation details
// ======================================================================
namespace xps::crypto::internal::compat::detail {

[[nodiscard]] inline std::size_t os_page_size() noexcept {
#if defined(XPS_OS_WINDOWS)
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    return si.dwPageSize ? static_cast<std::size_t>(si.dwPageSize)
                         : static_cast<std::size_t>(4096);
#else
    long ps = ::sysconf(_SC_PAGESIZE);
    return (ps > 0) ? static_cast<std::size_t>(ps)
                    : static_cast<std::size_t>(4096);
#endif
}

// Return a page-aligned region [astart, astart+alen) that fully covers [addr, addr+len)
[[nodiscard]] inline std::pair<std::uintptr_t, std::size_t>
page_align_region(void* addr, std::size_t len, std::size_t ps) noexcept {
    if (!addr || len == 0 || ps == 0) return {0u, 0u};
    const auto start = static_cast<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(addr));
    const auto end   = start + len;
    const auto astart = (start / ps) * ps;
    const auto aend   = ((end + ps - 1) / ps) * ps;
    const auto alen   = (aend >= astart) ? (aend - astart) : 0u;
    return { astart, alen };
}

// ---------------------- Secure Memory (non-exported) -------------------
class SecureMemoryImpl {
    static constexpr std::size_t MEMORY_LOCK_LIMIT = 64ull * 1024ull * 1024ull; // 64 MiB guard

public:
    [[nodiscard]] static ResultEx<std::monostate>
    lock_region(void* addr, std::size_t len) noexcept {
        if (addr == nullptr || len == 0) {
            return Err<std::monostate>(MakeError(
                ErrorCode::INVALID_PARAMETER,
                "Invalid memory region for locking",
                ErrorSeverity::MEDIUM,
                ErrorCategory::VALIDATION,
                "SecureMemory", "lock_region"
            ));
        }

        const std::size_t ps = os_page_size();
        const auto [aligned_start, aligned_len] = page_align_region(addr, len, ps);

        if (aligned_len == 0 || aligned_len > MEMORY_LOCK_LIMIT) {
            return Err<std::monostate>(MakeError(
                ErrorCode::INSUFFICIENT_MEMORY,
                "Memory region too large for locking",
                ErrorSeverity::MEDIUM,
                ErrorCategory::SYSTEM,
                "SecureMemory", "lock_region"
            ));
        }

#if defined(XPS_OS_WINDOWS)
        if (!::VirtualLock(reinterpret_cast<void*>(aligned_start), aligned_len)) {
            return Err<std::monostate>(MakeError(
                ErrorCode::IO_ERROR,
                "VirtualLock failed: " + std::to_string(::GetLastError()),
                ErrorSeverity::HIGH,
                ErrorCategory::SYSTEM,
                "SecureMemory", "lock_region"
            ));
        }
#else
        if (::mlock(reinterpret_cast<void*>(aligned_start), aligned_len) != 0) {
            const int ec = errno;
            return Err<std::monostate>(MakeError(
                ErrorCode::IO_ERROR,
                "mlock failed: " + std::to_string(ec),
                ErrorSeverity::HIGH,
                ErrorCategory::SYSTEM,
                "SecureMemory", "lock_region"
            ));
        }
#endif
        return Ok(std::monostate{});
    }

    [[nodiscard]] static ResultEx<std::monostate>
    unlock_region(void* addr, std::size_t len) noexcept {
        if (addr == nullptr || len == 0) return Ok(std::monostate{});

        const std::size_t ps = os_page_size();
        const auto [aligned_start, aligned_len] = page_align_region(addr, len, ps);
        if (aligned_len == 0) return Ok(std::monostate{});

#if defined(XPS_OS_WINDOWS)
        if (!::VirtualUnlock(reinterpret_cast<void*>(aligned_start), aligned_len)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_NOT_LOCKED) {
                return Err<std::monostate>(MakeError(
                    ErrorCode::IO_ERROR,
                    "VirtualUnlock failed: " + std::to_string(err),
                    ErrorSeverity::MEDIUM,
                    ErrorCategory::SYSTEM,
                    "SecureMemory", "unlock_region"
                ));
            }
        }
#else
        if (::munlock(reinterpret_cast<void*>(aligned_start), aligned_len) != 0) {
            const int ec = errno;
            if (ec != EINVAL && ec != ENOMEM) {
                return Err<std::monostate>(MakeError(
                    ErrorCode::IO_ERROR,
                    "munlock failed: " + std::to_string(ec),
                    ErrorSeverity::MEDIUM,
                    ErrorCategory::SYSTEM,
                    "SecureMemory", "unlock_region"
                ));
            }
        }
#endif
        return Ok(std::monostate{});
    }

    static void secure_clear(void* addr, std::size_t len) noexcept {
        if (!addr || len == 0) return;
        // Volatile wipe prevents the compiler from optimizing this out.
        volatile unsigned char* p = static_cast<volatile unsigned char*>(addr);
        for (std::size_t i = 0; i < len; ++i) p[i] = 0u;
        // Prevent reordering across the wipe.
        std::atomic_signal_fence(std::memory_order_seq_cst);
    }
};

// -------------------------- System RNG (non-exported) ------------------
class SystemRNGImpl {
public:
    [[nodiscard]] static ResultEx<std::monostate>
    get_random_bytes(unsigned char* out, std::size_t n) noexcept {
        if (!out) {
            return Err<std::monostate>(MakeError(
                ErrorCode::INVALID_PARAMETER,
                "Null output buffer for random bytes",
                ErrorSeverity::HIGH,
                ErrorCategory::VALIDATION,
                "SystemRNG", "get_random_bytes"
            ));
        }
        if (n == 0) return Ok(std::monostate{});

        // Defensive upper bound to avoid pathological requests.
        if (n > (256ull * 1024ull * 1024ull)) {
            return Err<std::monostate>(MakeError(
                ErrorCode::INSUFFICIENT_MEMORY,
                "Requested too many random bytes: " + std::to_string(n),
                ErrorSeverity::HIGH,
                ErrorCategory::SYSTEM,
                "SystemRNG", "get_random_bytes"
            ));
        }

#if defined(XPS_OS_WINDOWS)
        const NTSTATUS st = ::BCryptGenRandom(
            nullptr, out, static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(st)) {
            return Err<std::monostate>(MakeError(
                ErrorCode::HARDWARE_ERROR,
                "BCryptGenRandom failed: " + std::to_string(static_cast<unsigned long>(st)),
                ErrorSeverity::CRITICAL,
                ErrorCategory::CRYPTOGRAPHIC,
                "SystemRNG", "get_random_bytes"
            ));
        }
        return Ok(std::monostate{});

#else // POSIX families
  #if defined(__linux__)
        std::size_t off = 0;
        while (off < n) {
            const ssize_t r = ::getrandom(out + off, n - off, 0);
            if (r > 0) { off += static_cast<std::size_t>(r); continue; }
            if (r == 0) {
                return read_urandom(out + off, n - off);
            }
            if (errno == EINTR) continue;
            if (errno == ENOSYS) break; // Kernel doesn't support getrandom() -> fallback
            return Err<std::monostate>(MakeError(
                ErrorCode::HARDWARE_ERROR,
                "getrandom failed: " + std::to_string(errno),
                ErrorSeverity::HIGH,
                ErrorCategory::CRYPTOGRAPHIC,
                "SystemRNG", "get_random_bytes"
            ));
        }
        if (off == n) return Ok(std::monostate{});
  #elif defined(__APPLE__)
        if (CCRandomGenerateBytes(out, n) == kCCSuccess) return Ok(std::monostate{});
        // fallthrough to /dev/urandom
  #endif
        return read_urandom(out, n);
#endif
    }

private:
#if defined(XPS_OS_POSIX)
    [[nodiscard]] static ResultEx<std::monostate>
    read_urandom(unsigned char* out, std::size_t n) noexcept {
        int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return Err<std::monostate>(MakeError(
                ErrorCode::HARDWARE_ERROR,
                "Failed to open /dev/urandom: " + std::to_string(errno),
                ErrorSeverity::CRITICAL,
                ErrorCategory::SYSTEM,
                "SystemRNG", "read_urandom"
            ));
        }

        std::size_t off = 0;
        for (;;) {
            const ssize_t r = ::read(fd, out + off, n - off);
            if (r > 0) {
                off += static_cast<std::size_t>(r);
                if (off == n) break;
                continue;
            }
            if (r == 0) { // EOF unexpected
                ::close(fd);
                return Err<std::monostate>(MakeError(
                    ErrorCode::HARDWARE_ERROR,
                    "Unexpected EOF from /dev/urandom",
                    ErrorSeverity::CRITICAL,
                    ErrorCategory::SYSTEM,
                    "SystemRNG", "read_urandom"
                ));
            }
            const int ec = errno;
            if (ec == EINTR) continue;
            ::close(fd);
            return Err<std::monostate>(MakeError(
                ErrorCode::HARDWARE_ERROR,
                "Read from /dev/urandom failed: " + std::to_string(ec),
                ErrorSeverity::CRITICAL,
                ErrorCategory::SYSTEM,
                "SystemRNG", "read_urandom"
            ));
        }

        ::close(fd);
        return Ok(std::monostate{});
    }
#endif
};

} // namespace xps::crypto::internal::compat::detail

// ======================================================================
// Exported, minimal, stable API surface
// ======================================================================
export
namespace xps::crypto::internal::compat {

using Status = ResultEx<std::monostate>;

[[nodiscard]] inline Status OkStatus() { return Ok(std::monostate{}); }

// Memory locking
[[nodiscard]] inline Status lock_memory(void* addr, std::size_t len) noexcept {
    return detail::SecureMemoryImpl::lock_region(addr, len);
}

[[nodiscard]] inline Status unlock_memory(void* addr, std::size_t len) noexcept {
    return detail::SecureMemoryImpl::unlock_region(addr, len);
}

// Secure wipe
inline void secure_clear(void* addr, std::size_t len) noexcept {
    detail::SecureMemoryImpl::secure_clear(addr, len);
}

// System RNG
[[nodiscard]] inline Status sys_random_bytes(unsigned char* out, std::size_t n) noexcept {
    return detail::SystemRNGImpl::get_random_bytes(out, n);
}

// Page size (runtime)
[[nodiscard]] inline std::size_t page_size() noexcept {
    return detail::os_page_size();
}

// Capability probe: is memory locking plausibly supported/allowed?
[[nodiscard]] inline bool memory_locking_supported() noexcept {
#if defined(XPS_OS_WINDOWS)
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    // If the kernel gives us sane granularity, VirtualLock is supported.
    return si.dwAllocationGranularity > 0;
#else
    struct rlimit rl{};
    if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0) return false;
    // Some systems report RLIM_INFINITY; treat that as supported.
    return (rl.rlim_cur > 0) || (rl.rlim_cur == RLIM_INFINITY);
#endif
}

} // namespace xps::crypto::internal::compat

// -------- Clean up private macros (do not leak into importers) --------
#undef XPS_OS_WINDOWS
#undef XPS_OS_POSIX

