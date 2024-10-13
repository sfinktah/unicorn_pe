#pragma once
#include <distorm.h>

#include "InsnShimInterface.h"
class InsnDistorm : public InsnShimInterface
{
public:
	InsnDistorm() : insn({}) {}
    explicit InsnDistorm(_DInst insn) : insn(insn) {}

    [[nodiscard]] const _DInst& get() const {
		return insn;
	}

    ~InsnDistorm() override = default;
private:
    _DInst insn;
};

