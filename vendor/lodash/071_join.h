#pragma once
#include "lodash_common.h"

namespace _ {


	template<typename Container>
	std::string join_array(const Container& container, const char* const separator) {
		std::ostringstream os;
		// http://stackoverflow.com/a/5289170/912236
		// see also: https://stackoverflow.com/questions/191757/how-to-concatenate-a-stdstring-and-an-int

		const char* _separator = "";
		for (auto& item : container) {
			os << _separator << item;
			_separator = separator;
		}
		return os.str();
	}

	template<typename Container>
    std::string join_map(const Container& container, const char* const separator) {
        auto values = tuple_values _VECTOR(typename Container::value_type)(container);
        return join_array(values, separator);
    }

	template<typename Container>
	std::string join(const Container& container, const char* const separator) {
        if constexpr(traits::has_mapped_type<Container>::value) { 
            return join_map(container, separator);
        }
        else {
            return join_array(container, separator);
        }
	}
}
