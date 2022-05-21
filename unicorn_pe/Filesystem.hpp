#pragma once

#include <filesystem>
namespace fs = std::filesystem;
const fs::path& GetDllFolder();
std::string smart_path(const std::string& path);
std::string replace_extension(const std::string& path, const std::string& extension = "");
