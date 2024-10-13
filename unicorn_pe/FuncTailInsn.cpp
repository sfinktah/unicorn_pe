#include "FuncTailInsn.h"
#include <pystring/pystring.h>

#define String std::string

std::string FuncTailInsn::asString() const {
    return text();
}
std::string FuncTailInsn::text() const {
    String result(mnemonic_);
    if (!std::empty(operands_)) {
        result += " ";
        result += operands_;
    }
    return pystring::lower(result);
}

std::vector<FuncTailInsn> m_Instructions;
