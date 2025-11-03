module; // ===== Global Module Fragment =====
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <array>
#include <map>
#include <set>
#include <optional>
#include <cstring>
#include <variant>
#include <span>
#include <shared_mutex>
#include <mutex>
#include <algorithm>
#include <stdexcept>
#include <functional>
#include <sstream>
#include <type_traits>
#include <ctime>
#include <limits>
#include <utility>

export module xps.crypto.types;
export import xps.expected;
import xps.crypto.internal.common;
export namespace xps::crypto {

// ============================================================================
// Basic byte types
// ============================================================================
using Byte  = std::uint8_t;
using Bytes = std::vector<Byte>;

using KeyHandle   = std::string;
using AlgorithmID = std::string;
using UserID      = std::string;
using SessionID   = std::string;
using DomainID    = std::string;
using KeyID       = std::string;

// ============================================================================
// Secure utilities (zeroization, ct-equal)
// ============================================================================
namespace detail {

// Use std::memset_s when available; otherwise fall back to a volatile wipe.
inline void secure_memzero(void* p, std::size_t n) noexcept {
#if defined(__STDC_LIB_EXT1__)
    if (p && n) { ::memset_s(p, n, 0, n); }
#else
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
    for (std::size_t i = 0; i < n; ++i) vp[i] = 0u;
#endif
}

inline bool ct_equal(const Byte* a, const Byte* b, std::size_t n) noexcept {
    unsigned char acc = 0;
    for (std::size_t i = 0; i < n; ++i) acc |= static_cast<unsigned char>(a[i] ^ b[i]);
    return acc == 0;
}

// Portable UTC conversion helpers
inline std::tm gmtime_utc(std::time_t t) {
    std::tm out{};
#if defined(_WIN32)
    ::gmtime_s(&out, &t);
#elif defined(__unix__) || defined(__APPLE__)
    ::gmtime_r(&t, &out);
#else
    // Fallback (non-thread-safe). We copy the result to avoid shared static.
    if (auto* tmp = ::gmtime(&t)) out = *tmp;
#endif
    return out;
}

} // namespace detail

// ============================================================================
// SecureBuffer: RAII-secured, non-copyable, constant-time comparable buffer
// NOTE: Exposing raw pointers requires external synchronization if shared
// ============================================================================
class SecureBuffer {
    std::unique_ptr<Byte[]> data_{};
    std::size_t size_{0};
    std::size_t capacity_{0};
    mutable std::shared_mutex mtx_;

public:
    SecureBuffer() = default;

    explicit SecureBuffer(std::size_t size)
        : data_(size ? std::make_unique<Byte[]>(size) : nullptr),
          size_(size),
          capacity_(size) {
        if (data_) std::memset(data_.get(), 0, size_);
    }

    SecureBuffer(const Byte* src, std::size_t n) : SecureBuffer(n) {
        if (src && n) xps::crypto::internal::secure_copy(data_.get(), src, n);
    }

    // Move-only
    SecureBuffer(SecureBuffer&& other) noexcept { *this = std::move(other); }
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            secure_wipe();
            std::unique_lock lk(mtx_, std::defer_lock);
            std::unique_lock rk(other.mtx_, std::defer_lock);
            std::lock(lk, rk);
            data_ = std::move(other.data_);
            size_ = std::exchange(other.size_, 0);
            capacity_ = std::exchange(other.capacity_, 0);
        }
        return *this;
    }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    ~SecureBuffer() { secure_wipe(); }

    // Accessors (caller must ensure external synchronization for concurrent use)
    Byte* data() noexcept { return data_.get(); }
    const Byte* data() const noexcept { return data_.get(); }

    std::size_t size() const noexcept {
        std::shared_lock lk(mtx_);
        return size_;
    }
    std::size_t capacity() const noexcept {
        std::shared_lock lk(mtx_);
        return capacity_;
    }
    bool empty() const noexcept { return size() == 0; }

    void reserve(std::size_t new_capacity) {
        std::unique_lock lk(mtx_);
        if (new_capacity <= capacity_) return;
        auto new_mem = std::unique_ptr<Byte[]>(new Byte[new_capacity]{});
        if (data_ && size_) xps::crypto::internal::secure_copy(new_mem.get(), data_.get(), size_);
        // wipe old memory before releasing
        detail::secure_memzero(data_.get(), capacity_);
        data_ = std::move(new_mem);
        capacity_ = new_capacity;
    }

    void resize(std::size_t new_size) {
        std::unique_lock lk(mtx_);
        if (new_size > capacity_) {
            // grow (double strategy)
            std::size_t new_cap = std::max(new_size, capacity_ ? capacity_ * 2 : std::size_t(32));
            auto new_mem = std::unique_ptr<Byte[]>(new Byte[new_cap]{});
            if (data_ && size_) xps::crypto::internal::secure_copy(new_mem.get(), data_.get(), size_);
            detail::secure_memzero(data_.get(), capacity_);
            data_ = std::move(new_mem);
            capacity_ = new_cap;
        }
        if (new_size > size_) {
            // zero the newly exposed bytes
            std::memset(data_.get() + size_, 0, new_size - size_);
        } else if (new_size < size_) {
            // zero the truncated region
            detail::secure_memzero(data_.get() + new_size, size_ - new_size);
        }
        size_ = new_size;
    }

    void secure_wipe() noexcept {
        std::unique_lock lk(mtx_, std::defer_lock);
        if (!lk.try_lock()) {
            // best-effort wipe even if lock cannot be acquired (during stack unwinding)
            if (data_) detail::secure_memzero(data_.get(), capacity_);
            size_ = 0; capacity_ = 0;
            return;
        }
        if (data_) detail::secure_memzero(data_.get(), capacity_);
        size_ = 0;
        capacity_ = 0;
        data_.reset();
    }

    void copy_from(const Byte* src, std::size_t n) {
        if (!src && n) throw std::invalid_argument("copy_from: null src");
        resize(n);
        if (n) xps::crypto::internal::secure_copy(data_.get(), src, n);
    }

    void append(const Byte* src, std::size_t n) {
        if (!src && n) throw std::invalid_argument("append: null src");
        if (n == 0) return;
        std::size_t old = size();
        resize(old + n);
        xps::crypto::internal::secure_copy(data_.get() + old, src, n);
    }

    bool operator==(const SecureBuffer& other) const noexcept {
        std::shared_lock lk(mtx_, std::defer_lock);
        std::shared_lock rk(other.mtx_, std::defer_lock);
        std::lock(lk, rk);
        if (size_ != other.size_) return false;
        return detail::ct_equal(data_.get(), other.data_.get(), size_);
    }

    Byte& operator[](std::size_t i) {
        if (i >= size()) throw std::out_of_range("SecureBuffer::operator[]");
        return data_.get()[i];
    }
    const Byte& operator[](std::size_t i) const {
        if (i >= size()) throw std::out_of_range("SecureBuffer::operator[]");
        return data_.get()[i];
    }
};

// ============================================================================
// FixedSecureBuffer<N>: stack/inline buffer with zeroization & ct-compare
// ============================================================================
template<std::size_t N>
class FixedSecureBuffer {
    static_assert(N > 0, "FixedSecureBuffer size must be > 0");
    std::array<Byte, N> data_{};

public:
    FixedSecureBuffer() { data_.fill(0); }
    explicit FixedSecureBuffer(const std::array<Byte, N>& data) : data_(data) {}

    ~FixedSecureBuffer() { secure_wipe(); }

    void secure_wipe() noexcept { detail::secure_memzero(data_.data(), N); }

    constexpr std::size_t size() const noexcept { return N; }
    Byte* data() noexcept { return data_.data(); }
    const Byte* data() const noexcept { return data_.data(); }

    Byte& operator[](std::size_t idx) {
        if (idx >= N) throw std::out_of_range("FixedSecureBuffer index out of range");
        return data_[idx];
    }
    const Byte& operator[](std::size_t idx) const {
        if (idx >= N) throw std::out_of_range("FixedSecureBuffer index out of range");
        return data_[idx];
    }

    bool operator==(const FixedSecureBuffer& other) const noexcept {
        return detail::ct_equal(data_.data(), other.data_.data(), N);
    }
};

// Common fixed crypto types
using Hash256      = FixedSecureBuffer<32>;
using Hash512      = FixedSecureBuffer<64>;
using PublicKey32  = FixedSecureBuffer<32>;
using PublicKey64  = FixedSecureBuffer<64>;
using Signature64  = FixedSecureBuffer<64>;
using Signature128 = FixedSecureBuffer<128>;
using AesKey128    = FixedSecureBuffer<16>;
using AesKey256    = FixedSecureBuffer<32>;
using Nonce96      = FixedSecureBuffer<12>;
using Salt32       = FixedSecureBuffer<32>;

// ============================================================================
// Enums / bitflags
// ============================================================================
enum class AlgorithmType : std::uint16_t {
    UNKNOWN = 0,

    // Digital signatures
    ED25519 = 1,
    ED25519_PH = 2,
    RSA_2048 = 3,
    RSA_3072 = 4,
    RSA_4096 = 5,
    ECDSA_P256 = 6,
    ECDSA_P384 = 7,
    ECDSA_P521 = 8,
    ECDSA_SECP256K1 = 9,

    // Key exchange
    X25519 = 100,
    X448 = 101,
    ECDH_P256 = 102,
    ECDH_P384 = 103,
    ECDH_P521 = 104,

    // Post-quantum
    KYBER_512 = 200,
    KYBER_768 = 201,
    KYBER_1024 = 202,
    DILITHIUM_2 = 203,
    DILITHIUM_3 = 204,
    DILITHIUM_5 = 205,
    FALCON_512 = 206,
    FALCON_1024 = 207,

    // Hash
    SHA_256 = 300,
    SHA_384 = 301,
    SHA_512 = 302,
    SHA3_256 = 303,
    SHA3_384 = 304,
    SHA3_512 = 305,
    BLAKE2B_256 = 306,
    BLAKE2B_512 = 307,
    BLAKE3_256 = 308,

    // Symmetric AEAD
    AES_128_GCM = 400,
    AES_256_GCM = 401,
    CHACHA20_POLY1305 = 402
};

enum class KeyUsage : std::uint32_t {
    NONE           = 0,
    SIGNING        = 1u << 0,
    ENCRYPTION     = 1u << 1,
    KEY_EXCHANGE   = 1u << 2,
    VERIFICATION   = 1u << 3,
    DERIVATION     = 1u << 4,
    AUTHENTICATION = 1u << 5,
    CERTIFICATION  = 1u << 6,
    WRAP           = 1u << 7,
    UNWRAP         = 1u << 8,
    ALL            = 0xFFFFFFFFu
};

[[nodiscard]] inline constexpr KeyUsage operator|(KeyUsage a, KeyUsage b) noexcept {
    return static_cast<KeyUsage>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}
[[nodiscard]] inline constexpr KeyUsage operator&(KeyUsage a, KeyUsage b) noexcept {
    return static_cast<KeyUsage>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}
[[nodiscard]] inline constexpr KeyUsage operator~(KeyUsage a) noexcept {
    return static_cast<KeyUsage>(~static_cast<std::uint32_t>(a));
}
inline constexpr KeyUsage& operator|=(KeyUsage& a, KeyUsage b) noexcept { a = a | b; return a; }
[[nodiscard]] inline constexpr bool any(KeyUsage a, KeyUsage b) noexcept {
    return (static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b)) != 0u;
}
[[nodiscard]] inline constexpr bool all(KeyUsage a, KeyUsage b) noexcept {
    return (static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b)) == static_cast<std::uint32_t>(b);
}

enum class SecurityLevel : std::uint8_t {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    ULTRA = 4,
    QUANTUM_SAFE = 5
};

enum class KeyFormat : std::uint8_t { RAW, PEM, DER, JWK, HEX, BASE64, BASE64URL, BECH32, ASN1, PKCS8 };

enum class KeyOrigin : std::uint8_t { SOFTWARE = 0, HSM = 1, TPM = 2, SMART_CARD = 3, CLOUD_HSM = 4 };

enum class KeyState : std::uint8_t {
    ACTIVE = 0,
    INACTIVE = 1,
    COMPROMISED = 2,
    DESTROYED = 3,
    EXPIRED = 4,
    REVOKED = 5,
    PENDING_ACTIVATION = 6
};

enum class ErrorCode : std::int32_t {
    SUCCESS = 0,

    // Parameter errors
    INVALID_PARAMETER = 100,
    NULL_POINTER = 101,
    BUFFER_TOO_SMALL = 102,
    INVALID_SIZE = 103,
    UNSUPPORTED_FORMAT = 104,

    // Key errors
    INVALID_KEY_HANDLE = 200,
    KEY_NOT_FOUND = 201,
    KEY_EXPIRED = 202,
    KEY_REVOKED = 203,
    KEY_COMPROMISED = 204,
    KEY_STATE_INVALID = 205,
    KEY_USAGE_VIOLATION = 206,

    // Algorithm errors
    ALGORITHM_NOT_SUPPORTED = 300,
    OPERATION_NOT_SUPPORTED = 301,
    INVALID_SIGNATURE = 302,
    VERIFICATION_FAILED = 303,
    ENCRYPTION_FAILED = 304,
    DECRYPTION_FAILED = 305,

    // System errors
    INSUFFICIENT_MEMORY = 400,
    PERMISSION_DENIED = 401,
    HARDWARE_ERROR = 402,
    NETWORK_ERROR = 403,
    TIMEOUT = 404,
    INTERNAL_ERROR = 405,
    NOT_IMPLEMENTED = 406,
    CONFIG_ERROR = 407,
    IO_ERROR = 408
};

// ============================================================================
// Timestamp (UTC) with safe formatting/parsing
// ============================================================================
struct Timestamp {
    std::chrono::system_clock::time_point value;

    Timestamp() : value(std::chrono::system_clock::now()) {}
    explicit Timestamp(std::chrono::system_clock::time_point tp) : value(tp) {}

    [[nodiscard]] bool is_expired(std::chrono::seconds ttl) const {
        return (std::chrono::system_clock::now() - value) > ttl;
    }

    [[nodiscard]] std::string to_string() const {
        auto secs = std::chrono::time_point_cast<std::chrono::seconds>(value);
        std::time_t t = std::chrono::system_clock::to_time_t(secs);
        std::tm tm = detail::gmtime_utc(t);
        char buf[32]{};
        std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec);
        return std::string(buf);
    }

    // Accepts "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DDTHH:MM:SSZ" (UTC)
    static Timestamp from_string(const std::string& s) {
        int Y=0,M=0,D=0,h=0,m=0; int sec=0;
        if (s.size() >= 19 && (s[10] == ' ' || s[10] == 'T')) {
            std::sscanf(s.c_str(), "%d-%d-%d%*c%d:%d:%d", &Y, &M, &D, &h, &m, &sec);
        } else {
            throw std::invalid_argument("Timestamp::from_string: bad format");
        }
        using namespace std::chrono;
        const auto y = std::chrono::year{Y};
        const auto mo = std::chrono::month{static_cast<unsigned>(M)};
        const auto d = std::chrono::day{static_cast<unsigned>(D)};
        if (!y.ok() || !mo.ok() || !d.ok()) throw std::invalid_argument("Timestamp::from_string: invalid Y/M/D");
        sys_days days = sys_days(y/mo/d);
        auto tp = time_point<system_clock, seconds>(days.time_since_epoch())
                  + hours(h) + minutes(m) + seconds(sec);
        return Timestamp(system_clock::time_point(tp));
    }
};

// ============================================================================
// Key metadata & pair
// ============================================================================
struct KeyMetadata {
    KeyHandle handle;
    AlgorithmType algorithm{AlgorithmType::UNKNOWN};
    Timestamp created_at{};
    Timestamp updated_at{};
    std::optional<Timestamp> expires_at{};
    std::optional<Timestamp> not_before{};

    SecurityLevel security_level{SecurityLevel::HIGH};
    KeyUsage allowed_usage{KeyUsage::SIGNING};
    KeyUsage actual_usage{KeyUsage::NONE};
    KeyOrigin origin{KeyOrigin::SOFTWARE};
    KeyState state{KeyState::ACTIVE};

    std::vector<std::string> tags;
    std::size_t usage_count{0};
    std::size_t failed_attempts{0};

    std::string created_by;
    std::string description;
    std::string key_version{"1.0"};

    bool exportable{false};
    bool backup_required{true};
    bool hardware_protected{false};
    bool forward_secrecy{true};

    std::map<std::string, std::string> custom_attributes;

    bool operator==(const KeyMetadata& other) const {
        return handle == other.handle &&
               algorithm == other.algorithm &&
               security_level == other.security_level;
    }

    [[nodiscard]] bool is_active() const {
        return state == KeyState::ACTIVE || state == KeyState::PENDING_ACTIVATION;
    }

    [[nodiscard]] bool is_expired() const {
        return expires_at && expires_at->is_expired(std::chrono::seconds(0));
    }

    [[nodiscard]] bool can_use(KeyUsage usage) const {
        return any(allowed_usage, usage) && is_active() && !is_expired();
    }

    [[nodiscard]] std::string to_string() const {
        return "KeyMetadata[" + handle + ":" + std::to_string(static_cast<int>(algorithm)) + "]";
    }
};

struct KeyPair {
    SecureBuffer public_key;
    SecureBuffer private_key;
    SecureBuffer chain_code; // For hierarchical derivation (optional)
    KeyMetadata metadata;

    [[nodiscard]] bool is_valid() const {
        return !public_key.empty() && !private_key.empty() && metadata.is_active();
    }

    [[nodiscard]] std::size_t size() const {
        return public_key.size() + private_key.size() + chain_code.size();
    }

    [[nodiscard]] bool can_derive() const {
        return (chain_code.size() != 0) && any(metadata.allowed_usage, KeyUsage::DERIVATION);
    }
};

// ============================================================================
// Operation results
// ============================================================================
struct SignatureResult {
    SecureBuffer signature;
    ErrorCode error{ErrorCode::SUCCESS};
    std::string error_message;
    std::chrono::microseconds execution_time{0};
    std::size_t signature_size{0};
    Timestamp timestamp{};

    [[nodiscard]] bool success() const { return error == ErrorCode::SUCCESS; }
    explicit operator bool() const { return success(); }

    [[nodiscard]] std::string to_string() const {
        return success()
            ? ("Signature[ok:" + std::to_string(signature_size) + " bytes]")
            : ("Signature[err:" + error_message + "]");
    }
};

struct VerificationResult {
    bool is_valid{false};
    ErrorCode error{ErrorCode::SUCCESS};
    std::string error_message;
    std::chrono::microseconds execution_time{0};
    Timestamp timestamp{};

    explicit operator bool() const { return is_valid && error == ErrorCode::SUCCESS; }

    [[nodiscard]] std::string to_string() const {
        if (error != ErrorCode::SUCCESS) return "Verification[error:" + error_message + "]";
        return is_valid ? "Verification[valid]" : "Verification[invalid]";
    }
};

struct EncryptionResult {
    SecureBuffer ciphertext;
    SecureBuffer tag;
    SecureBuffer iv;
    ErrorCode error{ErrorCode::SUCCESS};
    std::string error_message;
    std::chrono::microseconds execution_time{0};
    Timestamp timestamp{};

    [[nodiscard]] bool success() const { return error == ErrorCode::SUCCESS; }
    explicit operator bool() const { return success(); }
};

struct DecryptionResult {
    SecureBuffer plaintext;
    ErrorCode error{ErrorCode::SUCCESS};
    std::string error_message;
    std::chrono::microseconds execution_time{0};
    Timestamp timestamp{};

    [[nodiscard]] bool success() const { return error == ErrorCode::SUCCESS; }
    explicit operator bool() const { return success(); }
};

// ============================================================================
// System & key configuration
// ============================================================================
struct SystemConfig {
    SecurityLevel default_security_level{SecurityLevel::HIGH};
    std::size_t max_key_handles{10000};
    std::size_t max_key_size{4096};
    std::size_t max_signature_size{512};
    std::size_t max_session_count{1000};

    bool enable_hardware_support{false};
    bool enable_biometric_integration{false};
    bool enable_quantum_resistance{true};

    std::string log_level{"INFO"};
    std::string audit_log_path{"audit.log"};

    std::chrono::seconds key_rotation_interval{std::chrono::hours(24 * 30)};
    std::chrono::seconds session_timeout{std::chrono::hours(1)};
    std::chrono::seconds cache_ttl{std::chrono::minutes(5)};

    bool strict_validation{true};
    bool fips_mode{false};
    bool enable_audit{true};
    bool enable_backup{true};

    std::vector<std::string> allowed_algorithms;
    std::vector<std::string> trusted_cas;

    static SystemConfig defaults() { return SystemConfig{}; }

    static SystemConfig high_security() {
        SystemConfig cfg;
        cfg.default_security_level = SecurityLevel::ULTRA;
        cfg.enable_hardware_support = true;
        cfg.enable_quantum_resistance = true;
        cfg.fips_mode = true;
        cfg.strict_validation = true;
        return cfg;
    }
};

struct KeyConfig {
    AlgorithmType algorithm{AlgorithmType::ED25519};
    SecurityLevel security_level{SecurityLevel::HIGH};
    KeyUsage usage{KeyUsage::SIGNING};
    KeyOrigin origin{KeyOrigin::SOFTWARE};

    std::chrono::seconds validity_period{std::chrono::hours(24 * 365)};
    std::chrono::seconds rotation_interval{std::chrono::hours(24 * 30)};

    std::vector<std::string> tags;
    bool exportable{false};
    bool backup_required{true};
    bool hardware_protected{false};
    bool enable_derivation{false};

    std::string description;
    std::string domain;

    static KeyConfig for_algorithm(AlgorithmType alg) {
        KeyConfig cfg;
        cfg.algorithm = alg;
        return cfg;
    }

    static KeyConfig for_hsm(AlgorithmType alg, SecurityLevel level = SecurityLevel::ULTRA) {
        KeyConfig cfg = for_algorithm(alg);
        cfg.origin = KeyOrigin::HSM;
        cfg.security_level = level;
        cfg.hardware_protected = true;
        cfg.exportable = false;
        return cfg;
    }

    static KeyConfig for_quantum_safe(AlgorithmType alg) {
        KeyConfig cfg = for_algorithm(alg);
        cfg.security_level = SecurityLevel::QUANTUM_SAFE;
        return cfg;
    }
};

// ============================================================================
// Monitoring & health
// ============================================================================
struct PerformanceMetrics {
    std::size_t operations_completed{0};
    std::size_t operations_failed{0};
    std::size_t operations_rejected{0};

    std::chrono::microseconds total_execution_time{0};
    std::chrono::microseconds min_execution_time{0};
    std::chrono::microseconds max_execution_time{0};

    double average_latency_ms{0.0};
    double p95_latency_ms{0.0};
    double p99_latency_ms{0.0};
    double throughput_ops_sec{0.0};

    std::size_t peak_memory_usage_bytes{0};
    std::size_t current_memory_usage_bytes{0};

    Timestamp start_time{};
    Timestamp last_update{};

    std::map<std::string, std::size_t> algorithm_usage;
    std::map<ErrorCode, std::size_t> error_distribution;
    std::map<std::string, std::size_t> operation_usage;

    void update_operation(bool ok,
                          std::chrono::microseconds duration,
                          const std::string& algorithm = {},
                          const std::string& operation = {},
                          ErrorCode err = ErrorCode::SUCCESS) {
        if (ok) ++operations_completed;
        else {
            ++operations_failed;
            if (err != ErrorCode::SUCCESS) error_distribution[err]++;
        }

        total_execution_time += duration;
        if (min_execution_time.count() == 0 || duration < min_execution_time) min_execution_time = duration;
        if (duration > max_execution_time) max_execution_time = duration;

        if (!algorithm.empty()) algorithm_usage[algorithm]++;
        if (!operation.empty()) operation_usage[operation]++;

        last_update = Timestamp{};
        update_derived_metrics();
    }

    void update_derived_metrics() {
        const auto total_ops = operations_completed + operations_failed;
        if (total_ops > 0) {
            average_latency_ms = static_cast<double>(total_execution_time.count()) / 1000.0 / static_cast<double>(total_ops);
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(last_update.value - start_time.value);
        if (elapsed.count() > 0) {
            throughput_ops_sec = static_cast<double>(total_ops) / static_cast<double>(elapsed.count());
        }
    }

    void reset() {
        *this = PerformanceMetrics{};
        start_time = Timestamp{};
        last_update = Timestamp{};
    }

    [[nodiscard]] std::string to_string() const {
        return "PerformanceMetrics[completed:" + std::to_string(operations_completed) +
               ", failed:" + std::to_string(operations_failed) +
               ", avg_latency:" + std::to_string(average_latency_ms) + "ms]";
    }
};

struct HealthStatus {
    bool system_healthy{false};
    bool database_healthy{false};
    bool hardware_healthy{false};
    bool network_healthy{false};

    std::map<std::string, bool> component_status;
    std::map<std::string, std::string> component_details;

    std::string overall_status;
    double system_load{0.0};
    double memory_usage{0.0};
    double disk_usage{0.0};

    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::vector<std::string> recommendations;

    Timestamp last_check{};
    PerformanceMetrics performance;

    [[nodiscard]] bool is_healthy() const {
        return system_healthy && database_healthy && hardware_healthy && network_healthy;
    }

    [[nodiscard]] std::string get_report() const {
        return overall_status + " (load: " + std::to_string(system_load) + "%)";
    }

    void add_component(const std::string& name, bool healthy, const std::string& details = {}) {
        component_status[name] = healthy;
        component_details[name] = details;
        update_overall_health();
    }

private:
    void update_overall_health() {
        system_healthy = std::all_of(component_status.begin(), component_status.end(),
                                     [](const auto& kv){ return kv.second; });
        overall_status = system_healthy ? "HEALTHY" : "DEGRADED";
    }
};

// ============================================================================
// Validation
// ============================================================================
struct ValidationResult {
    bool is_valid{false};
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;

    explicit operator bool() const { return is_valid; }

    void add_error(const std::string& e) { errors.push_back(e); is_valid = false; }
    void add_warning(const std::string& w) { warnings.push_back(w); }
    void add_recommendation(const std::string& r) { recommendations.push_back(r); }

    void merge(const ValidationResult& other) {
        is_valid = is_valid && other.is_valid;
        errors.insert(errors.end(), other.errors.begin(), other.errors.end());
        warnings.insert(warnings.end(), other.warnings.begin(), other.warnings.end());
        recommendations.insert(recommendations.end(), other.recommendations.begin(), other.recommendations.end());
    }

    [[nodiscard]] std::string to_string() const {
        if (is_valid && warnings.empty()) return "valid";
        if (is_valid) return "valid with " + std::to_string(warnings.size()) + " warnings";
        return "invalid: " + (errors.empty() ? "unknown error" : errors.front());
    }
};

// ============================================================================
// Concepts & helpers
// ============================================================================
template<typename T>
using Result = xps::expected<T, ErrorCode>;

using ConstByteSpan = std::span<const Byte>;
using ByteSpan      = std::span<Byte>;

using KeyEventCallback = std::function<void(const KeyHandle&,
                                            const std::string& /*event_type*/,
                                            const Timestamp&)>;
using SecurityEventCallback = std::function<void(const std::string& /*event_type*/,
                                                 const std::string& /*details*/,
                                                 SecurityLevel /*severity*/,
                                                 const Timestamp&)>;

} // namespace xps::crypto

