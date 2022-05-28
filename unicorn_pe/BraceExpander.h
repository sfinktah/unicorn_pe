#pragma once
#include <vector>
#include <string>
#include <sstream>

namespace sfinktah::string::brace_expander {
    std::vector<std::string> expand(const std::string& str);

    template <typename T>
    std::string join(const T& elements, std::string separator = ",") {
        std::ostringstream os;
        std::string _separator = "";
        for (const auto& item : elements) {
            os << _separator << item;
            _separator = separator;
        }
        return os.str();
    }

};  // namespace sfinktah::string::brace_expander
