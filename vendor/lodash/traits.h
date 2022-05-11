#pragma once

namespace _ {

    namespace detail {
        template <typename, template <typename...> typename T, typename... Args>
        struct is_detected : std::false_type {
        };

        template <template <typename...> typename T, typename... Args>
        struct is_detected<std::void_t<T<Args...>>, T, Args...> : std::true_type {
        };
    }  // namespace detail

    template <template <typename...> typename T, typename... Args>
    struct is_detected : detail::is_detected<void, T, Args...> {
    };

    namespace traits {
        template <typename Container>
        using push_back_t = decltype(std::declval<Container&>().push_back(std::declval<typename Container::value_type>()));

        template <typename Container>
        using emplace_back_t = decltype(std::declval<Container&>().emplace_back(std::declval<typename Container::value_type>()));

        template <typename Container>
        using has_push_back = is_detected<push_back_t, Container>;

        template <typename Container>
        using has_emplace_back = is_detected<emplace_back_t, Container>;

        template <typename Container>
        using mapped_type_t = typename Container::mapped_type;

        template <typename Container>
        using has_mapped_type = is_detected<mapped_type_t, Container>;

        template <typename Container>
        using is_object_t = decltype(std::declval<Container&>().is_object());

        template <typename Container>
        using has_is_object = is_detected<is_object_t, Container>;

        template <typename Container>
        using is_reserve_t = decltype(std::declval<Container&>().reserve(std::declval<typename Container::size_type>()));

        template <typename Container>
        using has_reserve = is_detected<is_reserve_t, Container>;

        // template<typename T> struct has_mapped_type {
        // private:
        //    template<typename U, typename = typename U::mapped_type>
        //    static int detect(U &&);
        //    static void detect(...);
        // public:
        //    static constexpr bool value =
        //        std::is_integral<decltype(detect(std::declval<T>()))>::value;
        //};
    }
}
