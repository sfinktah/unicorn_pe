#include "TemporaryFile.h"
#include "FileUtils.h"

TemporaryFile::TemporaryFile() {
    char name2[L_tmpnam];
    *name2 = 0;
    name = std::tmpnam(name2);
}

TemporaryFile::~TemporaryFile() {
    if (file_exists(name))
        file_remove(name);
}
