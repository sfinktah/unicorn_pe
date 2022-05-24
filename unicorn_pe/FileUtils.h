#pragma once
std::string GetLastErrorAsString();

namespace fs = std::filesystem;
using fspath = fs::path;

bool IsNewer(fspath sourcePath, fspath targetPath);

bool path_is_relative(const std::string& path);
fspath filepath(const std::string& path);
size_t file_size(const std::string& filename);

std::string basename(const std::string& path);
std::string dirname(const std::string& path);
std::string stem(const std::string& path);
std::string filename(const std::string& path);
std::string realpath(const std::string& path);
std::string extension(const std::string& path);

fs::path basename(const fs::path& path);
fs::path dirname(const fs::path& path);
fs::path stem(const fs::path& path);
fs::path filename(const fs::path& path);
fs::path realpath(const fs::path& path);
fs::path extension(const fs::path& path);

std::string filepath(fspath path);
std::string replace_filename(fspath, const fspath& filename);
std::string pathCombine(const std::string& path, const std::string& more);
std::wstring pathCombine(const std::wstring &path, const std::wstring &more);
std::string pathFold(const std::vector<std::string>& paths);
std::string replace_extension(const std::string& path, const std::string& extension);


bool file_exists(const std::string& path);
bool file_exists(const std::wstring& path);
bool file_remove(const std::string & path);
bool file_remove(const std::wstring & path);
bool is_dir(const std::string& path);
bool is_dir(const std::wstring & path);
bool is_relative(const std::string & path);

bool ensure_dir(const std::string & path);

