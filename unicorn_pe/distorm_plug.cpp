// diStorm64 library sample
// http://ragestorm.net/distorm/
// Arkon, Stefan, 2005
// Mikhail, 2006
// JvW, 2007

#include <cstdlib>
#include <cstdint>
#include <functional>
#include "FuncTailInsn.h"

#include "util.hpp"
#include "buffer.h"
#include "distorm_plug.h"

// For the compilers who don't have sysexits.h, which is not an ISO/ANSI include!
#define DISTORM_EX_OK           0
#define DISTORM_EX_SOFTWARE    70

#include <array>
#include <distorm.h>
#include <pystring/pystring.h>

// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define DISTORM_MAX_INSTRUCTIONS (1000)

int emu_disassemble(virtual_buffer_based_t& buffer, uintptr_t begin, uintptr_t end, const std::function<bool(FuncTailInsn)>& callback) {

    // Decoded instruction information.
    std::array<_DecodedInst, DISTORM_MAX_INSTRUCTIONS> decodedInstructions{};
    // next is used for instruction's offset synchronization.
    // decodedInstructionsCount holds the count of filled instructions' array by the decoder.
    unsigned int decodedInstructionsCount = 0;

    auto base       = buffer.GetBase();
    size_t filesize = buffer.GetLength();
    // Buffer to disassemble.
    unsigned char* buf = (unsigned char*)buffer.GetBuffer();

    _DecodeType dt     = Decode64Bits;
    _OffsetType offset = base;

    if (!begin) begin = buffer.GetBase();

    buf += begin - buffer.GetBase();
    if (!end)
        filesize -= begin - buffer.GetBase();
    else
        filesize = end - buffer.GetBase();

    // Decode the buffer at given offset (virtual address).
    while (true) {
        // If you get an undefined reference linker error for the following line,
        // change the SUPPORT_64BIT_OFFSET in distorm.h.
        _DecodeResult res = distorm_decode(offset, buf, (int)filesize, dt, decodedInstructions.data(), DISTORM_MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR) {
            // Null buffer? Decode type not 16/32/64?
            LOG_ERROR("Input error, halting!\n");
            return DISTORM_EX_SOFTWARE;
        }

        for (unsigned int i = 0; i < decodedInstructionsCount; i++) {
            FuncTailInsn fti;
            auto& di = decodedInstructions[i];

#ifndef X_DECOMPOSE
            _CodeInfo ci;
            _DInst de[2];
            unsigned int de_count = 0;
            ci.code = buf;
            ci.codeLen = (int)di.size;
            ci.codeOffset = di.offset;
            ci.dt = Decode64Bits;
            ci.features = DF_NONE; // https://github.com/gdabah/distorm/wiki/diStormFeatures
            res = distorm_decompose64(&ci, de, 1, &de_count);
            if (res == DECRES_SUCCESS) {
                auto insn = fti.insn(InsnDistorm{ de[0] });
            }
#endif
            
            fti.ea(di.offset).size((int)di.size).code(std::string((char*)buf, di.size)).mnemonic((char*)di.mnemonic.p);
            const char* _operands = (char*)di.operands.p;
            auto _rip             = string_between("[RIP", "]", _operands);
            if (!_rip.empty()) {
                std::string _replrip = string_between("[RIP", "]", _operands, STRING_BETWEEN_INCLUSIVE, [&](const std::string&) {
                    char* errch = nullptr;
                    int _offset = strtol(_rip.c_str(), &errch, 16);
                    if (*errch != '\0') {
                        LOG_ERROR("RIP Offset `%s' couldn't be converted.\n", _rip);
                    }
                    size_t _addr = di.offset + di.size + _offset;
                    return fmt::sprintf("[0x%llx]", _addr);
                });
                fti.operands(_replrip);
                // out << fmt::sprintf("%s %016llx (%02d) %-24s %s%s%s\n", name, 16, di.offset, di.size, (char*)di.instructionHex.p, (char*)di.mnemonic.p, di.operands.length != 0 ? " " : "", _replrip);
            } else if (di.operands.length) {
                fti.operands((char*)di.operands.p);
                // out << fmt::sprintf("%s %016llx (%02d) %-24s %s%s%s\n", name, 16, di.offset, di.size, (char*)di.instructionHex.p, (char*)di.mnemonic.p, di.operands.length != 0 ? " " : "", (char*)di.operands.p);
            } else {
            }
            if (callback(std::move(fti)))
                return DISTORM_EX_OK;

            // [d.address + o.disp + d.size for o in d.operands if o.type=='AbsoluteMemory']
        }
        if (res == DECRES_SUCCESS || decodedInstructionsCount == 0) break;  // All instructions were decoded.

        // Synchronize:
        auto next = (decodedInstructions[decodedInstructionsCount - 1].offset - offset);
        next += decodedInstructions[decodedInstructionsCount - 1].size;
        // Advance ptr and recalc offset.
        buf += next;
        filesize -= next;
        offset += next;
    }

    return DISTORM_EX_OK;
}
