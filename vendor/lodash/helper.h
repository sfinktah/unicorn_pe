#pragma once
#include "lodash_common.h"
#include "traits.h"

namespace _ {
    namespace helper {
        template <typename Container>
        typename std::enable_if<traits::has_push_back<Container>::value, void>::type 
        add_to_container(
            Container& container, const typename Container::value_type& value) {
            container.push_back(value);
        }

        template <typename Container>
        typename std::enable_if<traits::has_push_back<Container>::value, void>::type 
        add_to_container(
            Container& container, typename Container::value_type&& value) {
            container.push_back(std::move(value));
        }

        template <typename Container>
        typename std::enable_if < !traits::has_push_back<Container>::value, void >::type 
        add_to_container(
            Container& container, const typename Container::value_type& value) {
            container.insert(value);
        }

        template <typename Container>
        typename std::enable_if < !traits::has_push_back<Container>::value, void >::type 
        add_to_container(
            Container& container, typename Container::value_type&& value) {
            container.insert(std::move(value));
        }


        template <typename Container>
        void 
        add_to_container(
            Container& container, const typename Container::value_type& value, 
			const typename Container::iterator position) {
            container.insert(position, value);
        }

        template <typename T>
        constexpr const T& clamp(const T& val, const T& lo, const T& hi) {
            return (val < lo) ? lo : (val > hi) ? hi : val;
        }

        // https://stackoverflow.com/questions/9044866/how-to-get-the-number-of-arguments-of-stdfunction/9044927#9044927
        template <typename T>
        struct count_arg;

        template <typename R, typename... Args>
        struct count_arg<std::function<R(Args...)>> {
            static const size_t value = sizeof...(Args);
        };

        template <typename Argument, typename Function>
        class TransformCompare
#if _HAS_CXX17 == 0
            : std::binary_function<Argument, Argument, bool>
#endif
        {
        public:
            TransformCompare(Function const& func) : function_(func) {}

            bool operator()(Argument const& left, Argument const& right) const { return function_(left) < function_(right); }

        private:
            Function function_;
        };
    }  // namespace helper
}
