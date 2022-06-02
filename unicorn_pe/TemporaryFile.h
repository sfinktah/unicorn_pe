#pragma once
#include <string>
class TemporaryFile {
public:
    TemporaryFile();
    ~TemporaryFile();

    std::string name;
    operator std::string() const {
		return name;
	}
};
