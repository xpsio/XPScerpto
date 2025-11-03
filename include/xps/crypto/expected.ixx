module;
#include <concepts>
#include <functional>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <variant>
#include <memory>
#include <coroutine>
#include <exception>
#include <compare>

export module xps.expected;

export namespace xps {
    // ========== Control Policies ==========
    enum class expected_policy {
        throw_on_error,
        terminate_on_error,
        ignore_error
    };

    namespace detail {
        template <expected_policy P>
        struct policy_handler {
            static void handle_error() {
                if constexpr (P == expected_policy::throw_on_error) {
                    throw std::runtime_error("Expected access error");
                } else if constexpr (P == expected_policy::terminate_on_error) {
                    std::terminate();
                }
                // ignore_error: لا شيء
            }
        };
    }

    // ========== Control Tag ==========
    struct unexpect_t {};
    inline constexpr unexpect_t unexpect{};

    // ========== Unexpected Error Object ==========
    template <typename E>
    class [[nodiscard]] unexpected {
    public:
        using error_type = E;

        static_assert(!std::is_same_v<E, void>, "Error type cannot be void");
        static_assert(!std::is_reference_v<E>, "Error type cannot be a reference");

        template <typename Err = E>
        constexpr explicit unexpected(Err&& e)
            noexcept(std::is_nothrow_constructible_v<E, Err>)
            requires std::is_constructible_v<E, Err> &&
                     (!std::is_same_v<std::remove_cvref_t<Err>, unexpected>)
            : error_(std::forward<Err>(e)) {}

        template <typename... Args>
        constexpr explicit unexpected(std::in_place_t, Args&&... args)
            noexcept(std::is_nothrow_constructible_v<E, Args...>)
            requires std::is_constructible_v<E, Args...>
            : error_(std::forward<Args>(args)...) {}

        constexpr       E& error() &        noexcept { return error_; }
        constexpr const E& error() const &  noexcept { return error_; }
        constexpr       E&& error() &&      noexcept { return std::move(error_); }
        constexpr const E&& error() const&& noexcept { return std::move(error_); }

        template <typename E2>
        friend constexpr bool operator==(const unexpected& lhs,
                                         const unexpected<E2>& rhs)
            requires std::equality_comparable_with<E, E2>
        { return lhs.error() == rhs.error(); }

        template <typename E2>
        friend constexpr auto operator<=>(const unexpected& lhs,
                                          const unexpected<E2>& rhs)
            requires std::three_way_comparable_with<E, E2>
        { return lhs.error() <=> rhs.error(); }

    private:
        E error_;
    };

    // ========== Bad Expected Access Exception ==========
    template <typename E>
    class bad_expected_access : public std::exception {
    public:
        explicit bad_expected_access(E error)
            noexcept(std::is_nothrow_move_constructible_v<E>)
            : error_(std::move(error)) {}

        const char* what() const noexcept override {
            return "Bad expected access";
        }

        constexpr       E& error() &        noexcept { return error_; }
        constexpr const E& error() const &  noexcept { return error_; }
        constexpr       E&& error() &&      noexcept { return std::move(error_); }
        constexpr const E&& error() const&& noexcept { return std::move(error_); }

    private:
        E error_;
    };

    // ========== Forward Declaration ==========
    template <typename T, typename E, expected_policy P>
    class expected;

    // ========== Helper Concept ==========
    namespace detail {
        template <typename U>
        struct is_expected : std::false_type {};

        template <typename T, typename E, expected_policy P>
        struct is_expected< expected<T, E, P> > : std::true_type {};

        template <typename U>
        inline constexpr bool is_expected_v = is_expected<U>::value;
    }

    // ========== Advanced Storage ==========
    namespace detail {
        template <typename T, typename E>
        union storage {
            static_assert(!std::is_same_v<T, void>, "T cannot be void in storage");
            static_assert(!std::is_reference_v<T>, "T cannot be a reference");
            static_assert(!std::is_reference_v<E>, "E cannot be a reference");

            template <typename... Args>
            constexpr explicit storage(std::in_place_t, Args&&... args)
                noexcept(std::is_nothrow_constructible_v<T, Args...>)
                : value(std::forward<Args>(args)...) {}

            template <typename... Args>
            constexpr explicit storage(unexpect_t, Args&&... args)
                noexcept(std::is_nothrow_constructible_v<E, Args...>)
                : unexpect(std::forward<Args>(args)...) {}

            ~storage() {}

            T value;
            E unexpect;
        };

        template <typename E>
        union storage<void, E> {
            static_assert(!std::is_same_v<E, void>, "E cannot be void");
            static_assert(!std::is_reference_v<E>, "E cannot be a reference");

            constexpr storage() noexcept : dummy{} {}
            constexpr explicit storage(unexpect_t, const E& e)
                noexcept(std::is_nothrow_copy_constructible_v<E>)
                : unexpect(e) {}
            constexpr explicit storage(unexpect_t, E&& e)
                noexcept(std::is_nothrow_move_constructible_v<E>)
                : unexpect(std::move(e)) {}

            ~storage() {}

            std::monostate dummy;
            E unexpect;
        };

        // Performance sizing (احتياطي)
        template <typename T, typename E>
        struct expected_size
            : std::integral_constant<size_t,
                sizeof(storage<T, E>) + alignof(storage<T, E>)> {};

        template <typename T, typename E>
        constexpr bool use_sbo =
            (expected_size<T, E>::value <= 2 * sizeof(void*)) &&
            std::is_nothrow_move_constructible_v<T> &&
            std::is_nothrow_move_constructible_v<E>;
    }

    // ========== Core expected ==========
    template <typename T,
              typename E = std::exception_ptr,
              expected_policy Policy = expected_policy::throw_on_error>
    class [[nodiscard]] expected {
        using storage_t = detail::storage<T, E>;
        storage_t storage_;
        bool has_value_;

        constexpr void destroy() noexcept {
            if (has_value_) {
                if constexpr (!std::is_trivially_destructible_v<T>) {
                    storage_.value.~T();
                }
            } else {
                if constexpr (!std::is_trivially_destructible_v<E>) {
                    storage_.unexpect.~E();
                }
            }
        }

    public:
        using value_type = T;
        using error_type = E;
        using policy     = std::integral_constant<expected_policy, Policy>;

        // Value constructor
        template <typename... Args>
        constexpr expected(std::in_place_t, Args&&... args)
            noexcept(std::is_nothrow_constructible_v<T, Args...>)
            : storage_(std::in_place, std::forward<Args>(args)...)
            , has_value_(true) {}

        // Error constructor
        template <typename... Args>
        constexpr expected(unexpect_t, Args&&... args)
            noexcept(std::is_nothrow_constructible_v<E, Args...>)
            : storage_(unexpect, std::forward<Args>(args)...)
            , has_value_(false) {}

        // Construct from value
        template <typename U = T>
        constexpr expected(U&& value)
            noexcept(std::is_nothrow_constructible_v<T, U>)
            requires std::is_constructible_v<T, U> &&
                     (!std::same_as<std::remove_cvref_t<U>, expected>)
            : storage_(std::in_place, std::forward<U>(value))
            , has_value_(true) {}

        // Construct from unexpected
        template <typename Err>
        constexpr expected(unexpected<Err> e)
            noexcept(std::is_nothrow_constructible_v<E, Err>)
            requires std::is_constructible_v<E, Err>
            : storage_(unexpect, std::move(e.error()))
            , has_value_(false) {}

        // Copy ctor
        constexpr expected(const expected& other)
            requires (std::is_copy_constructible_v<T> &&
                      std::is_copy_constructible_v<E>)
            : storage_([&] {
                if (other.has_value_) {
                    return storage_t(std::in_place, other.storage_.value);
                } else {
                    return storage_t(unexpect, other.storage_.unexpect);
                }
            }())
            , has_value_(other.has_value_) {}

        // Move ctor
        constexpr expected(expected&& other) noexcept(
            std::is_nothrow_move_constructible_v<T> &&
            std::is_nothrow_move_constructible_v<E>)
            requires (std::is_move_constructible_v<T> &&
                      std::is_move_constructible_v<E>)
            : storage_([&] {
                if (other.has_value_) {
                    return storage_t(std::in_place, std::move(other.storage_.value));
                } else {
                    return storage_t(unexpect, std::move(other.storage_.unexpect));
                }
            }())
            , has_value_(other.has_value_) {}

        // Copy assignment
        constexpr expected& operator=(const expected& other)
            requires (std::is_copy_assignable_v<T> &&
                      std::is_copy_assignable_v<E>)
        {
            if (this != &other) {
                destroy();
                has_value_ = other.has_value_;
                if (has_value_) {
                    new (&storage_.value) T(other.storage_.value);
                } else {
                    new (&storage_.unexpect) E(other.storage_.unexpect);
                }
            }
            return *this;
        }

        // Move assignment
        constexpr expected& operator=(expected&& other) noexcept(
            std::is_nothrow_move_assignable_v<T> &&
            std::is_nothrow_move_assignable_v<E>)
            requires (std::is_move_assignable_v<T> &&
                      std::is_move_assignable_v<E>)
        {
            if (this != &other) {
                destroy();
                has_value_ = other.has_value_;
                if (has_value_) {
                    new (&storage_.value) T(std::move(other.storage_.value));
                } else {
                    new (&storage_.unexpect) E(std::move(other.storage_.unexpect));
                }
            }
            return *this;
        }

        // Destructor
        ~expected() { destroy(); }

        // Check presence
        constexpr bool has_value() const noexcept { return has_value_; }
        constexpr explicit operator bool() const noexcept { return has_value_; }

        // Access value (non-const lvalue)
        constexpr T& value() & {
            if (!has_value_) {
                if constexpr (Policy == expected_policy::throw_on_error) {
                    throw bad_expected_access<E>(storage_.unexpect);
                } else {
                    detail::policy_handler<Policy>::handle_error();
                    if constexpr (std::is_default_constructible_v<T>) {
                        static T dummy{};
                        return dummy;
                    } else {
                        std::terminate();
                    }
                }
            }
            return storage_.value;
        }

        // Access value (const lvalue)
        constexpr const T& value() const & {
            if (!has_value_) {
                if constexpr (Policy == expected_policy::throw_on_error) {
                    throw bad_expected_access<E>(storage_.unexpect);
                } else {
                    detail::policy_handler<Policy>::handle_error();
                    if constexpr (std::is_default_constructible_v<T>) {
                        static const T dummy{};
                        return dummy;
                    } else {
                        std::terminate();
                    }
                }
            }
            return storage_.value;
        }

        // Access value (rvalue) — يدعم move-only
        constexpr T&& value() && {
            if (!has_value_) {
                if constexpr (Policy == expected_policy::throw_on_error) {
                    throw bad_expected_access<E>(std::move(storage_.unexpect));
                } else {
                    detail::policy_handler<Policy>::handle_error();
                    if constexpr (std::is_default_constructible_v<T>) {
                        static T dummy{};
                        return std::move(dummy);
                    } else {
                        std::terminate();
                    }
                }
            }
            return std::move(storage_.value);
        }

        // Access error
        constexpr const E& error() const & noexcept { return storage_.unexpect; }
        constexpr       E& error()       & noexcept { return storage_.unexpect; }
        constexpr       E&& error()      && noexcept { return std::move(storage_.unexpect); }
        constexpr const E&& error() const&& noexcept { return std::move(storage_.unexpect); }

        // Pointer-like
        constexpr T* operator->() noexcept {
            return has_value_ ? &storage_.value : nullptr;
        }
        constexpr const T* operator->() const noexcept {
            return has_value_ ? &storage_.value : nullptr;
        }

        // Dereference
        constexpr T&       operator*() &        noexcept { return storage_.value; }
        constexpr const T& operator*() const &  noexcept { return storage_.value; }
        constexpr T&&      operator*() &&       noexcept { return std::move(storage_.value); }

        // and_then
        template <typename F>
        constexpr auto and_then(F&& f) & {
            using result_t = std::invoke_result_t<F, T&>;
            static_assert(detail::is_expected_v<result_t>,
                          "F must return an expected type");

            if (has_value_) {
                return std::invoke(std::forward<F>(f), storage_.value);
            }
            return result_t(unexpect, storage_.unexpect);
        }

        // or_else
        template <typename F>
        constexpr auto or_else(F&& f) & {
            using result_t = std::invoke_result_t<F, E&>;
            static_assert(detail::is_expected_v<result_t>,
                          "F must return an expected type");

            if (!has_value_) {
                return std::invoke(std::forward<F>(f), storage_.unexpect);
            }
            // نفترض أن result_t له نفس value_type = T
            if constexpr (std::is_void_v<T>) {
                return result_t();
            } else {
                return result_t(std::in_place, storage_.value);
            }
        }

        // transform
        template <typename F>
        constexpr auto transform(F&& f) & {
            using U = std::remove_cvref_t<std::invoke_result_t<F, T&>>;
            using result_t = expected<U, E>;

            if (has_value_) {
                if constexpr (std::is_void_v<U>) {
                    std::invoke(std::forward<F>(f), storage_.value);
                    return result_t(); // expected<void, E>
                } else {
                    return result_t(std::in_place,
                                    std::invoke(std::forward<F>(f), storage_.value));
                }
            }
            return result_t(unexpect, storage_.unexpect);
        }

        // transform_error
        template <typename F>
        constexpr auto transform_error(F&& f) & {
            using G = std::remove_cvref_t<std::invoke_result_t<F, E&>>;
            using result_t = expected<T, G>;

            if (!has_value_) {
                return result_t(unexpect,
                                std::invoke(std::forward<F>(f), storage_.unexpect));
            }
            if constexpr (std::is_void_v<T>) {
                return result_t();
            } else {
                return result_t(std::in_place, storage_.value);
            }
        }

        // value_or
        template <typename U>
        constexpr T value_or(U&& default_value) const&
            noexcept(std::is_nothrow_copy_constructible_v<T> &&
                     std::is_nothrow_convertible_v<U, T>)
            requires std::is_convertible_v<U, T>
        {
            return has_value_ ? storage_.value
                              : static_cast<T>(std::forward<U>(default_value));
        }

        // value_or_else
        template <typename F>
        constexpr T value_or_else(F&& f) const&
            noexcept(noexcept(std::invoke(std::forward<F>(f), storage_.unexpect)))
            requires std::is_invocable_r_v<T, F, E>
        {
            return has_value_ ? storage_.value
                              : std::invoke(std::forward<F>(f), storage_.unexpect);
        }

        // swap
        constexpr void swap(expected& other) noexcept(
            std::is_nothrow_swappable_v<T> &&
            std::is_nothrow_swappable_v<E>)
            requires (std::is_swappable_v<T> && std::is_swappable_v<E>)
        {
            using std::swap;
            if (has_value_ && other.has_value_) {
                swap(storage_.value, other.storage_.value);
            } else if (!has_value_ && !other.has_value_) {
                swap(storage_.unexpect, other.storage_.unexpect);
            } else {
                expected tmp = std::move(*this);
                *this = std::move(other);
                other = std::move(tmp);
            }
        }

        // emplace
        template <typename... Args>
        constexpr void emplace(Args&&... args) noexcept(
            std::is_nothrow_constructible_v<T, Args...>)
        {
            destroy();
            new (&storage_.value) T(std::forward<Args>(args)...);
            has_value_ = true;
        }
    };

    // ========== void Specialization ==========
    template <typename E, expected_policy Policy>
    class expected<void, E, Policy> {
        std::optional<E> error_;  // must come first
        bool has_value_;          // then has_value_

    public:
        using value_type = void;
        using error_type = E;
        using policy     = std::integral_constant<expected_policy, Policy>;

        // Success default (matches member order)
        constexpr expected() noexcept
            : error_(std::nullopt), has_value_(true) {}

        // Construct from unexpected
        template <typename Err>
        constexpr expected(unexpected<Err> e)
            noexcept(std::is_nothrow_constructible_v<E, Err>)
            requires std::is_constructible_v<E, Err>
            : error_(std::move(e.error())), has_value_(false) {}

        constexpr bool has_value() const noexcept { return has_value_; }
        constexpr explicit operator bool() const noexcept { return has_value_; }

        // value() for void
        constexpr void value() const {
            if (!has_value_) {
                if constexpr (Policy == expected_policy::throw_on_error) {
                    throw bad_expected_access<E>(*error_);
                } else {
                    detail::policy_handler<Policy>::handle_error();
                }
            }
        }

        constexpr const E& error() const & noexcept { return *error_; }
        constexpr       E& error()       & noexcept { return *error_; }
        constexpr       E&& error()      && noexcept { return std::move(*error_); }

        // and_then
        template <typename F>
        constexpr auto and_then(F&& f) const {
            using result_t = std::invoke_result_t<F>;
            static_assert(detail::is_expected_v<result_t>,
                          "F must return an expected type");

            if (has_value_) {
                return std::invoke(std::forward<F>(f));
            }
            return result_t(unexpect, *error_);
        }

        // or_else
        template <typename F>
        constexpr auto or_else(F&& f) const {
            using result_t = std::invoke_result_t<F, E&>;
            static_assert(detail::is_expected_v<result_t>,
                          "F must return an expected type");

            if (!has_value_) {
                return std::invoke(std::forward<F>(f), *error_);
            }
            return result_t();
        }

        // transform
        template <typename F>
        constexpr auto transform(F&& f) const {
            using U = std::remove_cvref_t<std::invoke_result_t<F>>;
            using result_t = expected<U, E>;

            if (has_value_) {
                if constexpr (std::is_void_v<U>) {
                    std::invoke(std::forward<F>(f));
                    return result_t();
                } else {
                    return result_t(std::in_place,
                                    std::invoke(std::forward<F>(f)));
                }
            }
            return result_t(unexpect, *error_);
        }

        // transform_error
        template <typename F>
        constexpr auto transform_error(F&& f) const {
            using G = std::remove_cvref_t<std::invoke_result_t<F, E&>>;
            using result_t = expected<void, G>;

            if (!has_value_) {
                return result_t(unexpect,
                                std::invoke(std::forward<F>(f), *error_));
            }
            return result_t();
        }

        // swap
        constexpr void swap(expected& other) noexcept(
            std::is_nothrow_swappable_v<E>)
            requires std::is_swappable_v<E>
        {
            if (has_value_ && other.has_value_) {
                // no-op
            } else if (!has_value_ && !other.has_value_) {
                using std::swap;
                swap(*error_, *other.error_);
            } else {
                expected tmp = std::move(*this);
                *this = std::move(other);
                other = std::move(tmp);
            }
        }
    };

    // ========== Factory Helpers ==========
    template <typename T, typename... Args>
    constexpr expected<T> make_expected(Args&&... args) {
        return expected<T>(std::in_place, std::forward<Args>(args)...);
    }

    template <typename E>
    constexpr auto make_unexpected(E&& err) {
        return unexpected<std::decay_t<E>>(std::forward<E>(err));
    }

    template <typename E, typename... Args>
    constexpr auto make_unexpected_from_args(Args&&... args) {
        return unexpected<E>(std::in_place, std::forward<Args>(args)...);
    }

    // ========== Comparison Operators ==========
    template <typename T, typename E, expected_policy P>
    constexpr bool operator==(const expected<T, E, P>& lhs,
                              const expected<T, E, P>& rhs) {
        if (lhs.has_value() != rhs.has_value()) return false;
        if (lhs.has_value()) {
            if constexpr (std::is_void_v<T>) {
                return true;
            } else {
                return *lhs == *rhs;
            }
        }
        return lhs.error() == rhs.error();
    }

    template <typename T, typename E, expected_policy P>
    constexpr auto operator<=>(const expected<T, E, P>& lhs,
                               const expected<T, E, P>& rhs)
        requires (std::three_way_comparable<T> || std::is_void_v<T>) &&
                 std::three_way_comparable<E>
    {
        if (lhs.has_value() && rhs.has_value()) {
            if constexpr (std::is_void_v<T>) {
                return std::strong_ordering::equal;
            } else {
                return *lhs <=> *rhs;
            }
        }
        if (!lhs.has_value() && !rhs.has_value()) {
            return lhs.error() <=> rhs.error();
        }
        return lhs.has_value()
                 ? std::strong_ordering::greater
                 : std::strong_ordering::less;
    }
}

// ========== std::hash Specialization ==========
namespace std {
    template <typename T, typename E, ::xps::expected_policy P>
    struct hash<::xps::expected<T, E, P>> {
        size_t operator()(const ::xps::expected<T, E, P>& exp) const {
            if (exp.has_value()) {
                if constexpr (std::is_void_v<T>) {
                    return std::hash<bool>{}(true);
                } else {
                    return std::hash<T>{}(*exp) ^ 0x9e3779b9;
                }
            }
            return std::hash<E>{}(exp.error());
        }
    };
}

