#pragma once
#include "001_each.h"

// will switch from boost to std::ranged with c++ 20 is realised
// using view_values = boost::range_detail::map_values_forwarder;
//using view_values = boost::adaptors::
    // C++20 version
// using values = std::views::values

namespace _ {
    template <typename T>
    struct get_arity : get_arity<decltype(&T::operator())> {};
    template <typename R, typename... Args>
    struct get_arity<R (*)(Args...)> : std::integral_constant<unsigned, sizeof...(Args)> {};
    template <typename R, typename C, typename... Args>
    struct get_arity<R (C::*)(Args...)> : std::integral_constant<unsigned, sizeof...(Args)> {};
    template <typename R, typename C, typename... Args>
    struct get_arity<R (C::*)(Args...) const> : std::integral_constant<unsigned, sizeof...(Args)> {};
    // All combinations of variadic/non-variadic, cv-qualifiers and ref-qualifiers

    //template <typename TFunc>
    //void printArity(TFunc) {
    //    std::cout << "arity: " << get_arity<TFunc>{} << std::endl;
    //}

    template <typename TFunc>
    void printArity(TFunc) {
       std::cout << "arity: " << get_arity<TFunc>{} << std::endl;
    }

    template <typename TFunc>
    constexpr int getArity(TFunc) {
        return get_arity<TFunc>{};
    }

    template <typename TFunc>
    constexpr int getArity() {
        return get_arity<TFunc>{};
    }


    using namespace nlohmann::detail;
    // http://en.cppreference.com/w/cpp/algorithm/for_each

template <typename T>
    using mapped_type_t = typename T::mapped_type;

    template <typename T>
    using key_type_t = typename T::key_type;

    template <typename T>
    using value_type_t = typename T::value_type;


template <typename T>
    using mapped_type_t = typename T::mapped_type;

    template <typename T>
    using key_type_t = typename T::key_type;

    template <typename T>
    using value_type_t = typename T::value_type;

template <typename T, typename = void>
    struct is_iterator_traits : std::false_type {};

    template <typename T>
    struct is_iterator_traits<iterator_traits<T>> {
    private:
        using traits = iterator_traits<T>;

    public:
        static constexpr auto value = is_detected<value_type_t, traits>::value && is_detected<difference_type_t, traits>::value &&
                                      is_detected<pointer_t, traits>::value && is_detected<iterator_category_t, traits>::value &&
                                      is_detected<reference_t, traits>::value;
    };


    template <typename CompatibleObjectType, typename = void>
    struct is_compatible_object_type_impl : std::false_type {};

    template <typename CompatibleObjectType>
    struct is_compatible_object_type_impl<CompatibleObjectType,
                                          std::enable_if_t<is_detected<mapped_type_t, CompatibleObjectType>::value &&
                                                           is_detected<key_type_t, CompatibleObjectType>::value>> {

        //using object_t = typename BasicJsonType::object_t;

        // macOS's is_constructible does not play well with nonesuch...
        static constexpr bool value = true;
            //std::is_constructible<typename object_t::key_type, typename CompatibleObjectType::key_type>::value &&
            //std::is_constructible<typename object_t::mapped_type, typename CompatibleObjectType::mapped_type>::value;
    };

    template <typename CompatibleObjectType>
    struct is_compatible_object_type : is_compatible_object_type_impl<CompatibleObjectType> {};


	template<typename CompatibleArrayType, typename = void>
	struct is_compatible_array_type_impl : std::false_type {};

	template<typename CompatibleArrayType>
	struct is_compatible_array_type_impl <
		CompatibleArrayType,
        std::enable_if_t < is_detected<value_type_t, CompatibleArrayType>::value&&
		is_detected<nlohmann::detail::iterator_t, CompatibleArrayType>::value&&
		// This is needed because json_reverse_iterator has a ::iterator type...
		// Therefore it is detected as a CompatibleArrayType.
		// The real fix would be to have an Iterable concept.
		!is_iterator_traits <
		iterator_traits<CompatibleArrayType >>::value >>
	{
		static constexpr bool value =
			std::is_constructible<
			typename CompatibleArrayType::value_type>::value;
	};

	template<typename CompatibleArrayType>
	struct is_compatible_array_type
		: is_compatible_array_type_impl<CompatibleArrayType> {};


    template <typename CompatibleArrayType, typename Function,
           enable_if_t < is_compatible_array_type<
                         CompatibleArrayType>::value &&
                         !is_compatible_object_type<CompatibleArrayType>::value &&
                         //!is_compatible_string_type<CompatibleArrayType>::value &&
                         !is_basic_json<CompatibleArrayType>::value,
                         int > = 0 >
    void each2(const CompatibleArrayType& array, Function&& iteratee) {
        if constexpr (getArity<Function>() == 1) {
            std::for_each(std::begin(array), std::end(array), std::forward<Function>(iteratee));
            return;
        } else if constexpr (get_arity<Function>{} == 2) {
            return _::each_with_distance(array, std::forward<Function>(iteratee));
        }
    }

    template <
		typename CompatibleObjectType, typename Function,
            enable_if_t< is_compatible_object_type<
                         CompatibleObjectType>::value && 
		                 !is_basic_json<CompatibleObjectType>::value,
                         int> = 0 >
    void each2(const CompatibleObjectType& obj, Function&& iteratee) {
        // https://stackoverflow.com/questions/13087028/can-i-easily-iterate-over-the-values-of-a-map-using-a-range-based-for-loop
        //  or brick - 
        // alternate way for associate container:
        // if constexpr(traits::has_mapped_type<Container>::value) 
        //    each(tuple_values _VECTOR(typename Container::value_type) (container, std::forward<Function>(iteratee)));
        if constexpr (get_arity<Function>{} == 1)
        {
            // boost being used temporarily as placeholder for C++20
            // for (auto const &i : foo | std::views::values)

            for (const auto&& i : obj/* | boost::adaptors::map_values*/)
				std::forward<Function>(iteratee)(i);
        } else if constexpr (get_arity<Function>{} == 2) {
            for (auto i = std::begin(obj); i != obj.end(); ++i)
                std::forward<Function>(iteratee)(i->second, i->first);
        }
    }

//    template <typename Container, typename Function>
//    void each2_magic(Container& container, Function&& iteratee) {
//        //if constexpr (std::is_invocable_r<bool, Function(typename Container::value_type)>::value)
//        // if constexpr (std::is_invocable<Function()>::value) 
//        if constexpr (get_arity<Function>{} == 1)
//        {
//            std::for_each(std::begin(container), std::end(container), std::forward<Function>(iteratee));
//        }
//#if __has_include("json.hpp") || defined(INCLUDE_NLOHMANN_JSON_HPP_)
//        else if constexpr (get_arity<Function>{} == 2 && traits::has_is_object<Container>::value)
//        {
//            for (auto i = std::begin(container); i != std::end(container); ++i)
//                std::forward<Function>(iteratee)(i.value(), i.key());
//        }
//        else if constexpr (get_arity<Function>{} == 1 && traits::has_is_object<Container>::value)
//        {
//            for (auto i = std::begin(container); i != std::end(container); ++i)
//                std::forward<Function>(iteratee)(i.value());
//        }
//        //else if constexpr (std::is_same_v<Container, nlohmann::basic_json<>>)
//        //{
//        //    for (auto i = std::begin(container); i != std::end(container); ++i)
//        //        std::forward<Function>(iteratee)(i.value(), i.key());
//        //}
//#endif
//        else if constexpr (get_arity<Function>{} == 2)
//        {
//            for (auto i = std::begin(container); i != std::end(container); ++i)
//                std::forward<Function>(iteratee)(i->second, i->first);
//        }
//        //else if constexpr (std::is_convertible<Function, typename Container::value_type>::value)
//        //{
//        //    return std::find(container.begin(), container.end(), std::forward<Function>(predicate));
//        //}
//        else 
//        {
//            // static_assert(!"Suck my dongle");
//            throw std::runtime_error("couldn't find appropriate method for _::find");
//        }
//        
//    }

}
