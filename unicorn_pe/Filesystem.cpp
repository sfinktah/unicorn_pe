#include <string>
#include "Filesystem.hpp"
#include <shlobj.h>
#include <fmt/format.h>

std::string ExePath() {

    char buffer[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleA(0), buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}

static fs::path GetDllFolderImpl() {
    // Get the documents folder.

    fs::path path = ExePath();

    path.append("Logs");
    OutputDebugStringA(path.string().c_str());
    try {
        if (fs::exists(path)) {
            if (!fs::is_directory(path)) {
                fs::remove(path);
                fs::create_directories(path);
            }
        } else {
            fs::create_directories(path);
        }
    } catch (...) {
        throw std::runtime_error("Failed to create logs folder.");
    }

    return path;
}

const fs::path& GetDllFolder() {
    static auto result = [] { return GetDllFolderImpl(); }();
    return result;
}

std::string smart_path(const std::string& path) {

	if (path.length() > 2) {
        if (path[0] == '/' && path[2] == '/' && isalpha(path[1])) {
            return fmt::format("{}:/{}", path.substr(1, 1), path.substr(3));
		}
	}
	return path;
}
