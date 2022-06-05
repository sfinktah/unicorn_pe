#pragma once
class YasmExt {
public:
    YasmExt(const std::string& string, uintptr_t origin);
	bool assemble(const std::string& filename, const std::string& objname, std::string& output, int& errorlevel);
	bool prep();
	std::string get_error();
    const std::vector<uint8_t>& get_assembled() const;

	std::string returned;
    std::string yasmPath, objPath, preInclude, asmPath, asmSource;
    std::vector<uint8_t> assembled;
	uintptr_t origin;
};
