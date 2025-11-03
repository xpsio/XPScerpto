module; // ===== Global Module Fragment =====
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <stdexcept>
#include <type_traits>
#include <concepts>
#include <optional>
#include <memory>
#include <cstring>
#include <atomic>
#include <functional>
#include <new>        // placement new
#include <source_location>

export module xps.crypto.errors;

import xps.crypto.types; // expects ErrorCode + common aliases

export namespace xps::crypto {

// ================================
// Advanced error types
// ================================

enum class ErrorSeverity : std::uint8_t {
    LOW,        // Non-critical — operation may continue
    MEDIUM,     // Needs attention
    HIGH,       // Critical — immediate handling advisable
    CRITICAL    // Security-threatening — stop immediately
};

enum class ErrorCategory : std::uint8_t {
    CRYPTOGRAPHIC,  // Algorithmic/cryptographic failures
    KEY_MANAGEMENT, // Key lifecycle/storage issues
    MEMORY_SAFETY,  // Memory integrity/clearing problems
    SYSTEM,         // OS/resources/hardware/environment
    VALIDATION,     // Input/format/range validation
    INTERNAL        // Invariants/logic errors
};

[[nodiscard]] inline constexpr std::string_view to_string(ErrorSeverity s) noexcept {
    switch (s) {
        case ErrorSeverity::LOW:      return "LOW";
        case ErrorSeverity::MEDIUM:   return "MEDIUM";
        case ErrorSeverity::HIGH:     return "HIGH";
        case ErrorSeverity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}
[[nodiscard]] inline constexpr std::string_view to_string(ErrorCategory c) noexcept {
    switch (c) {
        case ErrorCategory::CRYPTOGRAPHIC:  return "CRYPTOGRAPHIC";
        case ErrorCategory::KEY_MANAGEMENT: return "KEY_MANAGEMENT";
        case ErrorCategory::MEMORY_SAFETY:  return "MEMORY_SAFETY";
        case ErrorCategory::SYSTEM:         return "SYSTEM";
        case ErrorCategory::VALIDATION:     return "VALIDATION";
        case ErrorCategory::INTERNAL:       return "INTERNAL";
    }
    return "UNKNOWN";
}

class CryptoError {
    ErrorCode     code_{ErrorCode::INTERNAL_ERROR};
    std::string   msg_;
    ErrorSeverity severity_{ErrorSeverity::MEDIUM};
    ErrorCategory category_{ErrorCategory::INTERNAL};
    std::string   component_;
    std::string   operation_;
    std::uint64_t timestamp_{0}; // monotonic sequence per-process

public:
    CryptoError() = default;

    CryptoError(ErrorCode c, std::string m,
                ErrorSeverity s = ErrorSeverity::MEDIUM,
                ErrorCategory cat = ErrorCategory::INTERNAL,
                std::string comp = {},
                std::string op = {}) noexcept
        : code_(c),
          msg_(std::move(m)),
          severity_(s),
          category_(cat),
          component_(std::move(comp)),
          operation_(std::move(op)) {
        static std::atomic<std::uint64_t> counter{0};
        timestamp_ = ++counter;
    }

    // -------- Classification helpers --------

    [[nodiscard]] bool is_critical() const noexcept {
        return severity_ == ErrorSeverity::HIGH ||
               severity_ == ErrorSeverity::CRITICAL;
    }

    [[nodiscard]] bool should_retry() const noexcept {
        // Avoid retries on compromised keys or memory safety issues.
        return severity_ <= ErrorSeverity::MEDIUM &&
               code_ != ErrorCode::KEY_COMPROMISED &&
               category_ != ErrorCategory::MEMORY_SAFETY;
    }

    [[nodiscard]] bool should_clear_memory() const noexcept {
        return code_ == ErrorCode::KEY_COMPROMISED ||
               severity_ == ErrorSeverity::CRITICAL ||
               category_ == ErrorCategory::MEMORY_SAFETY;
    }

    [[nodiscard]] bool is_operational() const noexcept {
        // Treat typical transient/system conditions as operational.
        switch (code_) {
            case ErrorCode::TIMEOUT:
            case ErrorCode::NETWORK_ERROR:
            case ErrorCode::IO_ERROR:
            case ErrorCode::INSUFFICIENT_MEMORY:
            case ErrorCode::HARDWARE_ERROR:
                return true;
            default:
                break;
        }
        return category_ == ErrorCategory::SYSTEM;
    }

    [[nodiscard]] bool requires_immediate_action() const noexcept {
        return code_ == ErrorCode::KEY_COMPROMISED ||
               severity_ == ErrorSeverity::CRITICAL ||
               code_ == ErrorCode::HARDWARE_ERROR;
    }

    // -------- Accessors --------
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
    [[nodiscard]] ErrorSeverity severity() const noexcept { return severity_; }
    [[nodiscard]] ErrorCategory category() const noexcept { return category_; }
    [[nodiscard]] const std::string& message() const noexcept { return msg_; }
    [[nodiscard]] const std::string& component() const noexcept { return component_; }
    [[nodiscard]] const std::string& operation() const noexcept { return operation_; }
    [[nodiscard]] std::uint64_t timestamp() const noexcept { return timestamp_; }

    // -------- Formatting --------
    [[nodiscard]] std::string to_string() const {
        std::string out;
        out.reserve(128 + msg_.size() + component_.size() + operation_.size());
        out.append("CryptoError[code=").append(std::to_string(static_cast<int>(code_)));
        out.append(", sev=").append(xps::crypto::to_string(severity_));
        out.append(", cat=").append(xps::crypto::to_string(category_));
        out.append("] in ");
        if (!component_.empty()) out.append(component_); else out.append("<unknown>");
        out.append("::");
        if (!operation_.empty()) out.append(operation_); else out.append("<unknown>");
        out.append(" - ").append(msg_);
        return out;
    }

    [[nodiscard]] bool operator==(const CryptoError& other) const noexcept {
        return code_ == other.code_ && severity_ == other.severity_ &&
               category_ == other.category_;
    }
    [[nodiscard]] bool operator!=(const CryptoError& other) const noexcept {
        return !(*this == other);
    }

    [[noreturn]] void throw_as_exception() const {
        throw std::runtime_error(to_string());
    }
};

// ================================
// Crypto-safe type concepts
// ================================

template<typename T>
concept CryptoSafeType =
    std::is_nothrow_move_constructible_v<T> &&
    std::is_nothrow_destructible_v<T> &&
    !std::is_reference_v<T> &&
    !std::is_pointer_v<T>;

template<typename T>
concept HasSecureClear = requires(T t) { { t.secure_clear() } noexcept; };
template<typename T>
concept HasSecureWipe  = requires(T t) { { t.secure_wipe() } noexcept; };

template<typename T>
concept SecureClearable = HasSecureClear<T> || HasSecureWipe<T>;

// ================================
// ResultEx: outcome type (value or CryptoError)
// (kept distinct from xps::crypto::Result alias)
// ================================

template <CryptoSafeType T>
class [[nodiscard]] ResultEx {
    static_assert(!std::is_same_v<T, CryptoError>,
                  "ResultEx cannot hold CryptoError as a value");

    bool ok_{false};
    union {
        T           value_;
        CryptoError err_;
    };

    // -------- Secure lifecycle --------
    void cleanup() noexcept {
        if (ok_) {
            if constexpr (HasSecureClear<T>) {
                value_.secure_clear();
            } else if constexpr (HasSecureWipe<T>) {
                value_.secure_wipe();
            }
            value_.~T();
        } else {
            err_.~CryptoError();
        }
    }

    template<typename U>
    void construct_value(U&& v)
        noexcept(std::is_nothrow_constructible_v<T, U&&>) {
        ::new (static_cast<void*>(&value_)) T(std::forward<U>(v));
        ok_ = true;
    }

    void construct_error(const CryptoError& e)
        noexcept(std::is_nothrow_copy_constructible_v<CryptoError>) {
        ::new (static_cast<void*>(&err_)) CryptoError(e);
        ok_ = false;
    }
    void construct_error(CryptoError&& e)
        noexcept(std::is_nothrow_move_constructible_v<CryptoError>) {
        ::new (static_cast<void*>(&err_)) CryptoError(std::move(e));
        ok_ = false;
    }

public:
    // -------- Ctors / assignment --------
    ResultEx() = delete;

    template<typename U = T>
    requires std::is_constructible_v<T, U&&>
    explicit ResultEx(U&& v)
        noexcept(std::is_nothrow_constructible_v<T, U&&>) {
        construct_value(std::forward<U>(v));
    }

    explicit ResultEx(const CryptoError& e)
        noexcept(std::is_nothrow_copy_constructible_v<CryptoError>) {
        construct_error(e);
    }
    explicit ResultEx(CryptoError&& e)
        noexcept(std::is_nothrow_move_constructible_v<CryptoError>) {
        construct_error(std::move(e));
    }

    ResultEx(const ResultEx& other)
        noexcept(std::is_nothrow_copy_constructible_v<T> &&
                 std::is_nothrow_copy_constructible_v<CryptoError>) {
        if (other.ok_) construct_value(other.value_);
        else           construct_error(other.err_);
    }

    ResultEx(ResultEx&& other)
        noexcept(std::is_nothrow_move_constructible_v<T> &&
                 std::is_nothrow_move_constructible_v<CryptoError>) {
        if (other.ok_) construct_value(std::move(other.value_));
        else           construct_error(std::move(other.err_));
    }

    ResultEx& operator=(const ResultEx& other)
        noexcept(std::is_nothrow_copy_constructible_v<T> &&
                 std::is_nothrow_copy_constructible_v<CryptoError>) {
        if (this != &other) {
            cleanup();
            if (other.ok_) construct_value(other.value_);
            else           construct_error(other.err_);
        }
        return *this;
    }

    ResultEx& operator=(ResultEx&& other)
        noexcept(std::is_nothrow_move_constructible_v<T> &&
                 std::is_nothrow_move_constructible_v<CryptoError>) {
        if (this != &other) {
            cleanup();
            if (other.ok_) construct_value(std::move(other.value_));
            else           construct_error(std::move(other.err_));
        }
        return *this;
    }

    ~ResultEx() noexcept { cleanup(); }

    // -------- State checks --------
    [[nodiscard]] explicit operator bool() const noexcept { return ok_; }
    [[nodiscard]] bool has_value() const noexcept { return ok_; }
    [[nodiscard]] bool has_error() const noexcept { return !ok_; }
    [[nodiscard]] bool is_success() const noexcept { return ok_; }
    [[nodiscard]] bool is_failure() const noexcept { return !ok_; }

    // -------- Value access --------
    [[nodiscard]] const T& value() const & {
        if (!ok_) throw std::runtime_error(
            "Attempted to access value of failed ResultEx: " + err_.to_string());
        return value_;
    }
    [[nodiscard]] T& value() & {
        if (!ok_) throw std::runtime_error(
            "Attempted to access value of failed ResultEx: " + err_.to_string());
        return value_;
    }
    [[nodiscard]] T&& value() && {
        if (!ok_) throw std::runtime_error(
            "Attempted to access value of failed ResultEx: " + err_.to_string());
        return std::move(value_);
    }

    template<typename U>
    [[nodiscard]] T value_or(U&& def) const & {
        static_assert(std::is_convertible_v<U, T>,
                      "default value must be convertible to T");
        return ok_ ? value_ : static_cast<T>(std::forward<U>(def)); // requires T copyable
    }
    template<typename U>
    [[nodiscard]] T value_or(U&& def) && {
        static_assert(std::is_convertible_v<U, T>,
                      "default value must be convertible to T");
        return ok_ ? std::move(value_) : static_cast<T>(std::forward<U>(def));
    }
    template<typename F>
    [[nodiscard]] T value_or_eval(F&& f) const & {
        static_assert(std::is_invocable_r_v<T, F>, "f must return T");
        return ok_ ? value_ : std::invoke(std::forward<F>(f));
    }

    // -------- Error access --------
    [[nodiscard]] const CryptoError& error() const & {
        if (ok_) throw std::logic_error("No error in successful ResultEx");
        return err_;
    }
    [[nodiscard]] CryptoError&& error() && {
        if (ok_) throw std::logic_error("No error in successful ResultEx");
        return std::move(err_);
    }
    [[nodiscard]] std::optional<CryptoError> error_optional() const noexcept {
        if (ok_) return std::nullopt;
        return err_;
    }

    // -------- Transformations --------
    template<typename F>
    [[nodiscard]] auto transform(F&& f) const&
        -> ResultEx<std::invoke_result_t<F, const T&>> {
        using R = std::invoke_result_t<F, const T&>;
        static_assert(CryptoSafeType<R>, "transform() result must be crypto-safe");
        static_assert(!std::is_void_v<R>, "transform() cannot return void");
        if (!ok_) return ResultEx<R>(err_);
        try {
            return ResultEx<R>(std::invoke(std::forward<F>(f), value_));
        } catch (const std::exception& e) {
            return ResultEx<R>(CryptoError(
                ErrorCode::INTERNAL_ERROR,
                std::string("transform() failed: ") + e.what(),
                ErrorSeverity::MEDIUM, ErrorCategory::INTERNAL, "ResultEx::transform"));
        } catch (...) {
            return ResultEx<R>(CryptoError(
                ErrorCode::INTERNAL_ERROR,
                "transform() failed with unknown exception",
                ErrorSeverity::HIGH, ErrorCategory::INTERNAL, "ResultEx::transform"));
        }
    }
    template<typename F>
    [[nodiscard]] auto map(F&& f) const& -> decltype(this->transform(std::forward<F>(f))) {
        return transform(std::forward<F>(f));
    }

    // and_then: expects a function returning ResultEx<U>
    template<typename F>
    [[nodiscard]] auto and_then(F&& f) const& -> std::invoke_result_t<F, const T&> {
        using R = std::invoke_result_t<F, const T&>;
        if (!ok_) return R(err_);
        try {
            return std::invoke(std::forward<F>(f), value_);
        } catch (const std::exception& e) {
            return R(CryptoError(
                ErrorCode::INTERNAL_ERROR,
                std::string("and_then() failed: ") + e.what(),
                ErrorSeverity::MEDIUM, ErrorCategory::INTERNAL, "ResultEx::and_then"));
        } catch (...) {
            return R(CryptoError(
                ErrorCode::INTERNAL_ERROR,
                "and_then() failed with unknown exception",
                ErrorSeverity::HIGH, ErrorCategory::INTERNAL, "ResultEx::and_then"));
        }
    }
    template<typename F>
    [[nodiscard]] auto flat_map(F&& f) const& -> std::invoke_result_t<F, const T&> {
        return and_then(std::forward<F>(f));
    }

    // Apply side-effect, preserving the original ResultEx
    template<typename F>
    [[nodiscard]] ResultEx<T> for_each(F&& f) const& {
        if (ok_) {
            try { std::invoke(std::forward<F>(f), value_); }
            catch (...) { /* side-effects must not alter outcome */ }
        }
        return *this;
    }

    // -------- Error processing --------
    template<typename F>
    [[nodiscard]] ResultEx<T> map_error(F&& f) const& {
        static_assert(std::is_invocable_v<F, const CryptoError&>,
                      "map_error() function must be invocable with CryptoError");
        if (ok_) return *this;
        try {
            CryptoError e2 = std::invoke(std::forward<F>(f), err_);
            return ResultEx<T>(std::move(e2));
        } catch (const std::exception& e) {
            return ResultEx<T>(CryptoError(
                ErrorCode::INTERNAL_ERROR,
                std::string("map_error() failed: ") + e.what(),
                ErrorSeverity::MEDIUM, ErrorCategory::INTERNAL, "ResultEx::map_error"));
        } catch (...) {
            return ResultEx<T>(CryptoError(
                ErrorCode::INTERNAL_ERROR,
                "map_error() failed with unknown exception",
                ErrorSeverity::HIGH, ErrorCategory::INTERNAL, "ResultEx::map_error"));
        }
    }
    template<typename F>
    [[nodiscard]] ResultEx<T> or_else(F&& f) const& { return map_error(std::forward<F>(f)); }

    template<typename F>
    [[nodiscard]] ResultEx<T> recover(F&& f) const& {
        static_assert(std::is_invocable_r_v<T, F, const CryptoError&>,
                      "recover() function must return T");
        if (ok_) return *this;
        try {
            return ResultEx<T>(std::invoke(std::forward<F>(f), err_));
        } catch (const std::exception& e) {
            return ResultEx<T>(CryptoError(
                ErrorCode::INTERNAL_ERROR,
                std::string("recover() failed: ") + e.what(),
                ErrorSeverity::MEDIUM, ErrorCategory::INTERNAL, "ResultEx::recover"));
        } catch (...) {
            return ResultEx<T>(CryptoError(
                ErrorCode::INTERNAL_ERROR,
                "recover() failed with unknown exception",
                ErrorSeverity::HIGH, ErrorCategory::INTERNAL, "ResultEx::recover"));
        }
    }

    // -------- Advanced checks --------
    [[nodiscard]] bool has_critical_error() const noexcept {
        return !ok_ && err_.is_critical();
    }
    [[nodiscard]] bool should_retry() const noexcept {
        return !ok_ && err_.should_retry();
    }
    [[nodiscard]] bool requires_memory_clear() const noexcept {
        return !ok_ && err_.should_clear_memory();
    }
    [[nodiscard]] bool requires_immediate_action() const noexcept {
        return !ok_ && err_.requires_immediate_action();
    }
    [[nodiscard]] bool is_operational_error() const noexcept {
        return !ok_ && err_.is_operational();
    }

    // -------- Operators --------
    [[nodiscard]] const T& operator*() const & { return value(); }
    [[nodiscard]] T&       operator*() &       { return value(); }
    [[nodiscard]] T&&      operator*() &&      { return std::move(value()); }

    [[nodiscard]] const T* operator->() const { return &value(); }
    [[nodiscard]] T*       operator->()       { return &value(); }

    // -------- Swap --------
    void swap(ResultEx& other)
        noexcept(std::is_nothrow_swappable_v<T>) {
        using std::swap;
        if (ok_ && other.ok_) {
            swap(value_, other.value_);
        } else if (!ok_ && !other.ok_) {
            swap(err_, other.err_);
        } else {
            ResultEx tmp = std::move(*this);
            *this = std::move(other);
            other = std::move(tmp);
        }
    }
};

// ================================
// Helpers (Ok/Err + MakeError)
// ================================

template<typename T>
struct is_resultex : std::false_type {};
template<typename T>
struct is_resultex<ResultEx<T>> : std::true_type {};
template<typename T>
inline constexpr bool is_resultex_v = is_resultex<T>::value;

template <typename T>
[[nodiscard]] inline ResultEx<std::decay_t<T>> Ok(T&& v) {
    return ResultEx<std::decay_t<T>>(std::forward<T>(v));
}
template <typename T>
[[nodiscard]] inline ResultEx<T> Err(const CryptoError& e) {
    return ResultEx<T>(e);
}
template <typename T>
[[nodiscard]] inline ResultEx<T> Err(CryptoError&& e) {
    return ResultEx<T>(std::move(e));
}

[[nodiscard]] inline CryptoError MakeError(
    ErrorCode code, std::string msg,
    ErrorSeverity severity = ErrorSeverity::MEDIUM,
    ErrorCategory category = ErrorCategory::INTERNAL,
    std::string component = {},
    std::string operation = {}) noexcept {
    return CryptoError(code, std::move(msg), severity, category,
                       std::move(component), std::move(operation));
}

// ================================
// ErrorCode pickers + required helpers for other modules
// ================================
namespace detail {
  template <typename EC>
  constexpr EC pick_operation_cancelled() {
    if constexpr (requires { EC::OPERATION_CANCELLED; }) return EC::OPERATION_CANCELLED;
    else if constexpr (requires { EC::OperationCancelled; }) return EC::OperationCancelled;
    else if constexpr (requires { EC::CANCELLED; }) return EC::CANCELLED;
    else if constexpr (requires { EC::Cancelled; }) return EC::Cancelled;
    else if constexpr (requires { EC::CANCELLED_OPERATION; }) return EC::CANCELLED_OPERATION;
    else return EC::INTERNAL_ERROR;
  }

  template <typename EC>
  constexpr EC pick_operation_failed() {
    if constexpr (requires { EC::OPERATION_FAILED; }) return EC::OPERATION_FAILED;
    else if constexpr (requires { EC::OperationFailed; }) return EC::OperationFailed;
    else if constexpr (requires { EC::FAILED; }) return EC::FAILED;
    else if constexpr (requires { EC::FAILURE; }) return EC::FAILURE;
    else if constexpr (requires { EC::RUNTIME_ERROR; }) return EC::RUNTIME_ERROR;
    else return EC::INTERNAL_ERROR;
  }

  template <typename EC>
  constexpr EC pick_verification_failed() {
    if constexpr (requires { EC::VERIFICATION_FAILED; }) return EC::VERIFICATION_FAILED;
    else if constexpr (requires { EC::VerifyFailed; }) return EC::VerifyFailed;
    else if constexpr (requires { EC::SIGNATURE_INVALID; }) return EC::SIGNATURE_INVALID;
    else if constexpr (requires { EC::VALIDATION_FAILED; }) return EC::VALIDATION_FAILED;
    else if constexpr (requires { EC::VALIDATION_ERROR; }) return EC::VALIDATION_ERROR;
    else return EC::INTERNAL_ERROR;
  }
}

// These names are used by other modules (e.g., zero_downtime)
[[nodiscard]] constexpr ErrorCode operation_cancelled() noexcept {
  return detail::pick_operation_cancelled<ErrorCode>();
}
[[nodiscard]] constexpr ErrorCode operation_failed() noexcept {
  return detail::pick_operation_failed<ErrorCode>();
}
[[nodiscard]] constexpr ErrorCode verification_failed() noexcept {
  return detail::pick_verification_failed<ErrorCode>();
}

// Optional: direct CryptoError builders with sensible metadata
[[nodiscard]] inline CryptoError make_operation_cancelled(
    std::string msg = "Operation cancelled",
    std::string component = {}, std::string op = {}) noexcept {
  return MakeError(operation_cancelled(), std::move(msg),
                   ErrorSeverity::MEDIUM, ErrorCategory::SYSTEM,
                   std::move(component), std::move(op));
}
[[nodiscard]] inline CryptoError make_operation_failed(
    std::string msg = "Operation failed",
    std::string component = {}, std::string op = {}) noexcept {
  return MakeError(operation_failed(), std::move(msg),
                   ErrorSeverity::HIGH, ErrorCategory::SYSTEM,
                   std::move(component), std::move(op));
}
[[nodiscard]] inline CryptoError make_verification_failed(
    std::string msg = "Verification failed",
    std::string component = {}, std::string op = {}) noexcept {
  return MakeError(verification_failed(), std::move(msg),
                   ErrorSeverity::HIGH, ErrorCategory::VALIDATION,
                   std::move(component), std::move(op));
}

// Swap overload
template<typename T>
void swap(ResultEx<T>& a, ResultEx<T>& b) noexcept(noexcept(a.swap(b))) {
    a.swap(b);
}

} // namespace xps::crypto

// ================================
// std specializations (hash)
// ================================
export namespace std {

// Hash for xps::crypto::CryptoError
template<>
struct hash<xps::crypto::CryptoError> {
    size_t operator()(const xps::crypto::CryptoError& e) const noexcept {
        const auto code = static_cast<int>(e.code());
        const auto sev  = static_cast<int>(e.severity());
        const auto cat  = static_cast<int>(e.category());
        std::size_t h = std::hash<int>{}(code);
        h ^= (std::hash<int>{}(sev)  + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2));
        h ^= (std::hash<int>{}(cat)  + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2));
        h ^= (std::hash<std::uint64_t>{}(e.timestamp()) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2));
        return h;
    }
};

// Hash for xps::crypto::ResultEx<T> (enabled only if T is hashable)
template<typename T>
    requires requires (const T& t) { std::hash<T>{}(t); }
struct hash<xps::crypto::ResultEx<T>> {
    size_t operator()(const xps::crypto::ResultEx<T>& r) const {
        if (r.has_value()) {
            return std::hash<T>{}(*r) ^ 0x9e3779b9UL;
        } else {
            return std::hash<xps::crypto::CryptoError>{}(r.error());
        }
    }
};

} // namespace std

