#include <Windows.h>
#include "sniffing/nowide/convert.hpp"
#include "util.hpp"
#include <fmt/format.h>
#include <fmt/printf.h>
#include "maclog.h"
#if _HAS_CXX17 == 0
namespace std {
    namespace filesystem = experimental::filesystem;
}
#endif
namespace fs = std::filesystem;
using fspath = std::filesystem::path;
using namespace nowide;
#include "FileUtils.h"

// clang-format off
#define FS_TRY(...)                                                          \
    try {                                                                    \
        __VA_ARGS__;                                                         \
    }                                                                        \
    catch (const fs::filesystem_error& e)                                    \
    {                                                                        \
        LOG_INFO(__FUNCTION__ ": std::filesystem::exception: {}", e.what()); \
    }                                                                        \
    catch (const std::invalid_argument& e) {                                 \
        LOG_INFO(__FUNCTION__ ": std::invalid_argument: {}", e.what());      \
    }                                                                        \
    catch (const std::exception &e) {                                        \
        LOG_INFO(__FUNCTION__ ": std::exception: {}", e.what());             \
    }

// clang-format on

// see ErrorExit for a bigger implementation
std::string GetLastErrorAsString() {
    // Get the error message, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) return "No error";  // No error message has been recorded

    char* messageBuffer = nullptr;
    size_t size =
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                       errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&messageBuffer, 0, nullptr);

    std::string message(messageBuffer, size);

    // Free the buffer.
    LocalFree(messageBuffer);

    return message;
}

bool IsNewer(fspath sourcePath, fspath targetPath) {
    if (!fs::exists(sourcePath)) {
        LOG_WARN("File not found: {}", sourcePath.string().c_str());
        // trigger exception
        volatile auto unused = fs::last_write_time(sourcePath);
        return false;
    }
    if (!fs::exists(targetPath)) return true;
    if (fs::last_write_time(sourcePath) > fs::last_write_time(targetPath)) return true;
    return false;
}

// realpath() expands all symbolic links and resolves references to /./, /../ and extra / characters in the input path and returns
// the canonicalized absolute pathname.
std::string realpath(const std::string& path) {
    fspath dir(path);
    std::error_code ec;
    auto rv = fs::canonical(dir, ec);
    if (!ec) return dir.string();
    return rv.string();
}

std::string extension(const std::string& path) { return fspath(path).extension().string(); }

std::string pathCombine(const std::string& path, const std::string& more) {
    try {
        return (fspath(path) / fspath(more)).string();
    } catch (std::invalid_argument) {
        return path + "\\" + more;
    }
}

std::wstring pathCombine(const std::wstring& path, const std::wstring& more) {

    try {
        fspath dir(path);
        fspath file(more);
        fspath full_path = dir / file;
        return full_path.wstring();
    } catch (std::invalid_argument) {
        return path + L"\\" + more;
    }
}

// dirname — Returns a parent directory's path
std::string dirname(const std::string& path) {
    fspath dir(path);
    fspath dirname = dir.parent_path();
    return dirname.string();
}

// basename — Returns trailing name component of path
std::string basename(const std::string& path) {
    fspath dir(path);
    fspath basename = dir.filename();
    return basename.string();
}

// pick off stem (basename) in filename (leaf) before dot
std::string stem(const std::string& path) {
    fspath dir(path);
    fspath stem = dir.stem();
    return stem.string();
}

// basename — Returns trailing name component of path
std::string filename(const std::string& path) {
    fspath dir(path);
    fspath filename = dir.filename();
    return filename.string();
}

std::string replace_filename(fspath path, const fspath& filename) { return path.replace_filename(filename).string(); }

// string extension from filename.ext
std::string replace_extension(const std::string& path, const std::string& extension) {
    fspath dir(path);
    // do we need to widen the extension??? really??
    fspath dirname = dir.replace_extension(extension);
    return dirname.string();
}

bool path_is_relative(const std::string& path) {
    fspath dir(path);
    return dir.is_relative();
}

/// <summary>
/// Convert string to fspath
/// </summary>
/// <param name="path"></param>
/// <returns></returns>
fspath filepath(const std::string& path) { return fspath(path); }

/// <summary>
/// Convert fspath to string
/// </summary>
/// <param name="path"></param>
/// <returns></returns>
std::string filepath(fspath path) {
    auto test  = path.u8string();
    auto test2 = path.string();
    return test2;
}

size_t file_size(const std::string& filename) {
    return fs::file_size(filename);
    // http://stackoverflow.com/a/32286531/912236
    std::filesystem::path p{filename};
    p = std::filesystem::canonical(p);
    return std::filesystem::file_size(p);
    // std::cout << "The size of " << p.u8string() << " is " << fs::file_size(p) << " bytes.\n";
}

// Determines whether a path to a file system object such as a file or folder is valid.
bool file_exists(const std::string& path) {
    FS_TRY(return fs::exists(path));
    return false;
}
// Determines whether a path to a file system object such as a file or folder is valid.
bool file_exists(const std::wstring& path) {
    FS_TRY(return std::filesystem::exists(fspath(path)));
    return false;
}

bool file_remove(const std::string& path) {
    FS_TRY(return std::filesystem::remove(path));
    return false;
}
bool file_remove(const std::wstring& path) {
    FS_TRY(return std::filesystem::remove(path));
    return false;
}

bool is_dir(const std::string& path) {
    if (!file_exists(path)) return false;
    FS_TRY(return std::filesystem::is_directory(fspath(path)));
    return false;
    // return PathIsDirectoryW(widen(path).c_str());
}

bool is_dir(const std::wstring& path) {
    if (!file_exists(path)) return false;
    FS_TRY(return std::filesystem::is_directory(fspath(path)));
    return false;
}

bool is_relative(const std::string& path) {
    FS_TRY(return fspath(path).is_relative());
    return false;
}

bool ensure_dir(const std::string& path) {
    std::string subdir = path;
    if (!file_exists(subdir)) {
        if (!CreateDirectoryW(widen(subdir).c_str(), nullptr)) {
            LOG_ERROR("Couldn't create directory: {}", subdir.c_str());
            return false;  // directory not there, and can't make
        }
        return true;  // return true is directory was made
    }
    if (!is_dir(subdir)) {
        LOG_ERROR("Path was file, not directory: {}", (subdir));
        return false;
    }
    return true;  // return true if directory already there (or can't be made)
}
