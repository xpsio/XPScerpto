module; // ===== Global Module Fragment =====
#include <cstdint>
#include <cstddef>
#include <string_view>
#include <chrono>
#include <algorithm>
#include <new> // std::hardware_destructive_interference_size

export module xps.crypto.config;

import xps.crypto.types;       // SystemConfig, SecurityLevel, ...
import xps.crypto.build_info;  // build::*

// =============================
// Internal (not exported)
// =============================
namespace xps::crypto::detail {

template <typename = void>
consteval std::size_t cache_line_size_impl() {
  if constexpr (requires { std::hardware_destructive_interference_size; }) {
    return std::hardware_destructive_interference_size;
  } else {
    return 64;
  }
}

consteval bool is_pow2(std::size_t n) { return n && ((n & (n - 1)) == 0); }

template <class T>
constexpr T clamp_min(T v, T lo) { return std::max(v, lo); }

template <class T>
constexpr T clamp_max(T v, T hi) { return std::min(v, hi); }

template <class T>
constexpr T clamp(T v, T lo, T hi) { return std::min(hi, std::max(lo, v)); }

} // namespace xps::crypto::detail

// =============================
// Public API (exported)
// =============================
export namespace xps::crypto {

// ============================================================================
// Version & build info (forwarded from build_info)
// ============================================================================
namespace version {
  inline constexpr std::uint32_t MAJOR = build::MAJOR;
  inline constexpr std::uint32_t MINOR = build::MINOR;
  inline constexpr std::uint32_t PATCH = build::PATCH;

  inline constexpr std::string_view NAME           = build::NAME;
  inline constexpr std::string_view VERSION_STRING = build::VERSION_STRING;
  inline constexpr std::string_view BUILD_DATE     = build::BUILD_DATE;
  inline constexpr std::string_view BUILD_TIME     = build::BUILD_TIME;

  inline constexpr std::uint32_t API_VERSION = build::API_VERSION;
  inline constexpr std::uint32_t ABI_VERSION = build::ABI_VERSION;
}

// ============================================================================
// Hardware/OS constants and safe limits
// ============================================================================
namespace constants {
  inline constexpr std::size_t CACHE_LINE_SIZE   = detail::cache_line_size_impl<>();
  inline constexpr std::size_t PAGE_SIZE_BYTES   = 4096;

  inline constexpr std::size_t MAX_KEY_SIZE_BYTES   = 512;
  inline constexpr std::size_t MAX_IV_SIZE_BYTES    = 64;
  inline constexpr std::size_t MAX_TAG_SIZE_BYTES   = 64;
  inline constexpr std::size_t MAX_BLOCK_SIZE_BYTES = 256;
  inline constexpr std::size_t MAX_SALT_SIZE_BYTES  = 64;

  inline constexpr std::size_t   MAX_STACK_BUFFER_SIZE     = 4096;                      // 4 KiB
  inline constexpr std::size_t   MAX_SINGLE_OPERATION_SIZE = 128 * 1024 * 1024;         // 128 MiB
  inline constexpr std::size_t   MAX_STREAM_OPERATION_SIZE = 1ULL * 1024 * 1024 * 1024; // 1 GiB
  inline constexpr std::uint32_t MAX_OPERATION_RETRIES     = 3;

  static_assert(detail::is_pow2(CACHE_LINE_SIZE) && CACHE_LINE_SIZE <= 256,
                "Unexpected cache line size.");
}

// ============================================================================
// Algorithm families (config-layer enums)
// ============================================================================
enum class HashAlgorithm      { SHA256, SHA384, SHA512, SHA3_256, SHA3_512, BLAKE3_256 };
enum class CipherAlgorithm    { AES256_GCM, AES128_GCM, CHACHA20_POLY1305 };
enum class KeyDerivationAlgorithm { ARGON2ID, HKDF_SHA256, PBKDF2_HMAC_SHA256 };
enum class SignatureAlgorithm { ED25519, ECDSA_P256, ECDSA_SECP256K1, RSA_PSS_2048 };
enum class RandomAlgorithm    { SYSTEM, CTR_DRBG, HMAC_DRBG };

namespace algorithms {
  inline constexpr HashAlgorithm          DEFAULT_HASH      = HashAlgorithm::SHA256;
  inline constexpr CipherAlgorithm        DEFAULT_CIPHER    = CipherAlgorithm::AES256_GCM;
  inline constexpr KeyDerivationAlgorithm DEFAULT_KDF       = KeyDerivationAlgorithm::ARGON2ID;
  inline constexpr SignatureAlgorithm     DEFAULT_SIGNATURE = SignatureAlgorithm::ED25519;
  inline constexpr RandomAlgorithm        DEFAULT_RANDOM    = RandomAlgorithm::SYSTEM;
}

// ============================================================================
// Security/KDF tuning
// ============================================================================
struct KdfParams {
  std::uint32_t iterations  = 100'000;
  std::uint32_t memory_kib  = 65'536;  // 64 MiB
  std::uint32_t parallelism = 1;
  std::uint32_t salt_bytes  = 32;      // 256-bit
};

namespace security {
  inline constexpr std::uint32_t MIN_ITERATIONS = 1'000;
  inline constexpr std::uint32_t MIN_MEMORY_KiB = 8'192; // 8 MiB
  inline constexpr std::uint32_t MIN_SALT_BYTES = 16;    // 128-bit
}

struct Compatibility {
  bool enable_legacy_algorithms = false;
  bool strict_mode              = true;
  bool fips_mode                = false; // normalize() will enforce FIPS when true
  bool use_big_endian           = false;
  bool enable_pkcs7_padding     = true;
  constexpr bool operator==(const Compatibility&) const = default;
};

struct AlgorithmDefaults {
  HashAlgorithm          hash      = algorithms::DEFAULT_HASH;
  CipherAlgorithm        cipher    = algorithms::DEFAULT_CIPHER;
  KeyDerivationAlgorithm kdf       = algorithms::DEFAULT_KDF;
  SignatureAlgorithm     signature = algorithms::DEFAULT_SIGNATURE;
  RandomAlgorithm        random    = algorithms::DEFAULT_RANDOM;
  constexpr bool operator==(const AlgorithmDefaults&) const = default;
};

struct LibraryVersion {
  std::uint32_t    major      = version::MAJOR;
  std::uint32_t    minor      = version::MINOR;
  std::uint32_t    patch      = version::PATCH;
  std::uint32_t    api        = version::API_VERSION;
  std::uint32_t    abi        = version::ABI_VERSION;
  std::string_view name       = version::NAME;
  std::string_view ver_str    = version::VERSION_STRING;
  std::string_view built_date = version::BUILD_DATE;
  std::string_view built_time = version::BUILD_TIME;
  constexpr bool operator==(const LibraryVersion&) const = default;
};

// ============================================================================
// High-level configuration object
// ============================================================================
struct RuntimeLimits {
  std::size_t   max_stack_buffer_size     = constants::MAX_STACK_BUFFER_SIZE;
  std::size_t   max_single_operation_size = constants::MAX_SINGLE_OPERATION_SIZE;
  std::size_t   max_stream_operation_size = constants::MAX_STREAM_OPERATION_SIZE;
  std::uint32_t max_operation_retries     = constants::MAX_OPERATION_RETRIES;
  constexpr bool operator==(const RuntimeLimits&) const = default;
};

struct CryptoConfig {
  SystemConfig       system{};  // from xps.crypto.types
  AlgorithmDefaults  alg{};
  KdfParams          kdf{};
  RuntimeLimits      limits{};
  Compatibility      compat{};
  LibraryVersion     ver{};
  // SystemConfig may not be equality-comparable; forbid accidental use.
  bool operator==(const CryptoConfig&) const = delete;
};

// ============================================================================
// Factory presets
// ============================================================================
[[nodiscard]] inline CryptoConfig get_configuration_defaults() {
  CryptoConfig cfg{};
  cfg.system = SystemConfig::defaults();
  return cfg;
}

[[nodiscard]] inline CryptoConfig get_high_security_config() {
  using namespace std::chrono;
  CryptoConfig cfg = get_configuration_defaults();

  cfg.system.default_security_level    = SecurityLevel::ULTRA;
  cfg.system.enable_hardware_support   = true;
  cfg.system.enable_quantum_resistance = true;
  cfg.system.fips_mode                 = true;   // enforced by normalize()
  cfg.system.strict_validation         = true;
  cfg.system.enable_backup             = true;
  cfg.system.key_rotation_interval     = duration_cast<std::chrono::seconds>(std::chrono::days{30});

  cfg.kdf.iterations  = std::max(cfg.kdf.iterations * 2, security::MIN_ITERATIONS);
  cfg.kdf.memory_kib  = std::max(cfg.kdf.memory_kib * 2, security::MIN_MEMORY_KiB);
  cfg.kdf.salt_bytes  = 64;
  cfg.kdf.parallelism = std::max<std::uint32_t>(cfg.kdf.parallelism, 2);

  cfg.compat.enable_legacy_algorithms = false;
  cfg.compat.strict_mode = true;
  cfg.compat.fips_mode   = true;

  return cfg;
}

[[nodiscard]] inline CryptoConfig get_high_performance_config() {
  CryptoConfig cfg = get_configuration_defaults();

  cfg.system.strict_validation = true;
  cfg.kdf.iterations  = security::MIN_ITERATIONS;
  cfg.kdf.memory_kib  = security::MIN_MEMORY_KiB;
  cfg.kdf.parallelism = 4;
  cfg.limits.max_operation_retries = 1;

  return cfg;
}

[[nodiscard]] inline CryptoConfig get_balanced_config() {
  CryptoConfig cfg = get_configuration_defaults();
  cfg.system.strict_validation = true;
  cfg.kdf.iterations  = std::max<std::uint32_t>(50'000, security::MIN_ITERATIONS);
  cfg.kdf.memory_kib  = std::max<std::uint32_t>(32'768, security::MIN_MEMORY_KiB); // 32 MiB
  cfg.kdf.parallelism = 2;
  return cfg;
}

[[nodiscard]] inline CryptoConfig get_compatibility_config() {
  CryptoConfig cfg = get_configuration_defaults();

  cfg.compat.enable_legacy_algorithms = true;
  cfg.compat.strict_mode = false;
  cfg.compat.enable_pkcs7_padding = true;

  cfg.system.fips_mode = false;
  cfg.system.strict_validation = false;

  return cfg;
}

// ============================================================================
// Normalization: clamp limits + enforce FIPS when requested
// ============================================================================
inline void normalize(CryptoConfig& cfg) {
  // KDF bounds
  cfg.kdf.iterations  = detail::clamp_min(cfg.kdf.iterations,  security::MIN_ITERATIONS);
  cfg.kdf.memory_kib  = detail::clamp_min(cfg.kdf.memory_kib,  security::MIN_MEMORY_KiB);
  cfg.kdf.salt_bytes  = detail::clamp(cfg.kdf.salt_bytes, security::MIN_SALT_BYTES,
                                      static_cast<std::uint32_t>(constants::MAX_SALT_SIZE_BYTES));
  cfg.kdf.parallelism = detail::clamp_min(cfg.kdf.parallelism, 1u);

  // Runtime limits
  cfg.limits.max_stack_buffer_size     =
      detail::clamp_max(cfg.limits.max_stack_buffer_size,     constants::MAX_STACK_BUFFER_SIZE);
  cfg.limits.max_single_operation_size =
      detail::clamp_max(cfg.limits.max_single_operation_size, constants::MAX_SINGLE_OPERATION_SIZE);
  cfg.limits.max_stream_operation_size =
      detail::clamp_max(cfg.limits.max_stream_operation_size, constants::MAX_STREAM_OPERATION_SIZE);
  cfg.limits.max_operation_retries     =
      detail::clamp_max(cfg.limits.max_operation_retries,     constants::MAX_OPERATION_RETRIES);

  // FIPS enforcement
  if (cfg.compat.fips_mode) {
    cfg.system.fips_mode = true;
    cfg.compat.strict_mode = true;
    cfg.compat.enable_legacy_algorithms = false;

    if (cfg.alg.kdf == KeyDerivationAlgorithm::ARGON2ID) {
      cfg.alg.kdf = KeyDerivationAlgorithm::PBKDF2_HMAC_SHA256;
    }
    if (cfg.alg.signature == SignatureAlgorithm::ED25519) {
      cfg.alg.signature = SignatureAlgorithm::ECDSA_P256;
    }
    if (cfg.alg.random == RandomAlgorithm::SYSTEM) {
      cfg.alg.random = RandomAlgorithm::HMAC_DRBG;
    }
    cfg.alg.cipher = CipherAlgorithm::AES256_GCM;
    cfg.alg.hash   = HashAlgorithm::SHA256;
  }
}

// Convenience: return presets already normalized
[[nodiscard]] inline CryptoConfig make_high_security()    { auto c = get_high_security_config();    normalize(c); return c; }
[[nodiscard]] inline CryptoConfig make_high_performance() { auto c = get_high_performance_config(); normalize(c); return c; }
[[nodiscard]] inline CryptoConfig make_balanced()         { auto c = get_balanced_config();         normalize(c); return c; }
[[nodiscard]] inline CryptoConfig make_compatibility()    { auto c = get_compatibility_config();    normalize(c); return c; }

// ============================================================================
// Validation & version helpers
// ============================================================================
[[nodiscard]] inline bool check_api_compatibility(std::uint32_t required_api_version) noexcept {
  return required_api_version <= version::API_VERSION;
}

[[nodiscard]] inline constexpr std::string_view get_version_string() noexcept {
  return version::VERSION_STRING;
}
[[nodiscard]] inline constexpr std::string_view get_library_name() noexcept {
  return version::NAME;
}

[[nodiscard]] inline bool validate_configuration(
    const CryptoConfig& cfg,
    std::uint32_t required_api_version = version::API_VERSION) noexcept
{
  if (cfg.kdf.iterations   < security::MIN_ITERATIONS)            return false;
  if (cfg.kdf.memory_kib   < security::MIN_MEMORY_KiB)            return false;
  if (cfg.kdf.salt_bytes   < security::MIN_SALT_BYTES)            return false;
  if (cfg.kdf.salt_bytes   > constants::MAX_SALT_SIZE_BYTES)      return false;

  if (cfg.limits.max_stack_buffer_size     > constants::MAX_STACK_BUFFER_SIZE)     return false;
  if (cfg.limits.max_single_operation_size > constants::MAX_SINGLE_OPERATION_SIZE) return false;
  if (cfg.limits.max_stream_operation_size > constants::MAX_STREAM_OPERATION_SIZE) return false;
  if (cfg.limits.max_operation_retries     > constants::MAX_OPERATION_RETRIES)     return false;

  if (!check_api_compatibility(required_api_version)) return false;

  if (cfg.compat.fips_mode && !cfg.system.fips_mode) return false;

  return true;
}

} // namespace xps::crypto

