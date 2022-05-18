#pragma once
#define String std::string
#define VectorString std::vector<String>

#define GETSET(TYPE, FN, DEFAULT) \
    GETSET2(TYPE, FN, FN##_, DEFAULT)

#define GETSET2(TYPE, FN, VAR, DEFAULT) \
    SETONLY(TYPE, FN, VAR);             \
    GETONLY(TYPE, FN, VAR);             \
    VARONLY(TYPE, VAR, DEFAULT)

#define GETSETONLY(TYPE, FN, VAR) \
    SETONLY(TYPE, FN, VAR);       \
    GETONLY(TYPE, FN, VAR)

#define GETONLY(TYPE, FN, VAR) \
    METHOD TYPE FN() const { return VAR; }

#define SETONLY(TYPE, FN, VAR)   \
    METHOD CLASS& FN(TYPE VAR) { \
        auto r       = *this;    \
        return r.VAR = VAR, *this;   \
    }

#undef VARONLY
#define VARONLY(TYPE, VAR, DEFAULT) \
    TYPE VAR = DEFAULT

#define METHOD virtual
#undef CLASS
#define CLASS FuncTailInsn

class FuncTailInsn {
public:
    GETSET(String, text, {});
    GETONLY(String, insn, text_);            
    GETSET(uintptr_t, ea, {});
    GETSET(int, sp, {});
    GETSET(int, spd, {});
    GETSET(String, code, {});
    GETSET(String, operands, {});
    GETSET(String, mnemonic, {});
    GETSET(int, size, {});
    GETSET(uintptr_t, target, {});

    // self._insn_comments = comments
    // self._insn_warnings = warnings
    // self._insn_errors = errors
    // self._insn_chunkhead = chunkhead
    // self._insn_labels = labels
    // self._insn_insn = insn
    // self._insn_refs_from = refs_from
    // self._insn_refs_to = refs_to
    // self._insn_flow_refs_from = flow_refs_from
    // self._insn_flow_refs_to = flow_refs_to

	std::string asString() {
		return text_;
	}
};

#undef String
#undef VectorString
