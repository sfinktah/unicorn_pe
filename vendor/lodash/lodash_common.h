#pragma once
#include <vector>
#include <functional>
#include <iterator>
#include "./traits.h"
#ifndef NLOHMANN_JSON_VERSION_MAJOR
// template<typename> struct is_basic_json : std::false_type {};
#include <nlohmann/json.hpp>
#endif
using namespace nlohmann::detail;

#define _VECTOR(...) <std::vector<__VA_ARGS__>>
#define _LIST(...) <std::list<__VA_ARGS__>>
