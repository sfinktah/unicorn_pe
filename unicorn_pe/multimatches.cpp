#ifdef USE_BOOST
#include "multimatches.h"
#include "../vendor/lodash/075_first.h"
#include "sniffing/HexDump.h"
//#include "membricksafe.hpp"
#include "FuncTailInsn.h"
//using mbs = membricksafe::memBrickSafe;
std::vector<MultiMatch> multimatches;

void init_multimatches() {

    multimatches.emplace_back(

        "call via push rbp, lea, xchg && jmp imm",
        std::vector<std::string>{
            R"(push rbp)",
            R"(lea rbp, \[[::rel::]({jtarget}[::address::])\])",
            R"(xchg [::qword_ptr::]\[rsp\], rbp)",
            R"(jmp ({ctarget}[::address::]))",
        },
        std::vector<std::string>{R"(call ${ctarget})"});

    //multimatches.emplace_back(

    //    "mini-cmov", 
    //    std::vector<std::string>{R"(push rbp)", R"(movabs rbp, ({raxtarget}[::address::]))", R"(xchg [::qword_ptr::]\[rsp\], rbp)", R"(push ({rax}[::r64::]))", R"(push ({rcx}[::r64::]))", R"(mov ${rax}, [::qword_ptr::]\[rsp\+0x10\])", R"(movabs ${rcx}, ({rcxtarget}[::address::]))", R"(({cmov}cmov\w+) ${rax}, ${rcx})", R"(mov [::qword_ptr::]\[rsp\+0x10\], ${rax})", R"(pop ${rcx})", R"(pop ${rax})", R"(ret)"},
    //    [](std::vector<FuncTailInsn>& instructions, group_t capture_groups, map_fti_index insn_groups, vector_fti_index insn_list) -> std::string {
    //        auto rax_target    = asQwordO(_::firstOpt(capture_groups["raxtarget"]), 16);
    //        auto rcx_target    = asQwordO(_::firstOpt(capture_groups["rcxtarget"]), 16);
    //        if (auto _cmov_insn = _::firstOpt(insn_groups["cmov"]); _cmov_insn && rax_target && rcx_target) {
    //            auto* cmov_insn = &instructions[*_cmov_insn];
    //            auto cmov_addr  = cmov_insn->ea();
    //            auto condition  = (cmov_insn->code()[2] & 0x0f) ^ 0x01;

    //            // auto condition = mbs(cmov_addr).cmovcc();
    //            LOG("cmov: {} {:x} condition: {:x}", cmov_insn->text(), cmov_insn->ea(), condition);
    //            HexDump::dumpBytesAsHex(*outs, cmov_insn->code());
    //            std::string response;
    //            response.resize(5 + 6 + 1);
    //            auto start = instructions[insn_list[0]].ea();
    //            mbs(start)
    //                .jcc(*rax_target, condition)  // flip condition to negative proposition to match un-obfu code
    //                .jmp(*rcx_target)
    //                .db(0xCC);
    //        }
    //    });

    multimatches.emplace_back(

        "jmp via push rbp, lea, xchg && ret",
        std::vector<std::string>{
            R"(push rbp)",
            R"(lea rbp, \[[::rel::]({jtarget}[::address::])\])",
            R"(xchg [::qword_ptr::]\[rsp\], rbp)",
            R"(ret)",
        },
        std::vector<std::string>{R"(jmp ${jtarget})"});

    multimatches.emplace_back(

        "push via mov [rsp-0x8], reg; lea rsp, [rsp-0x8]",
        std::vector<std::string>{
            R"(mov [::qword_ptr::]\[rsp-0x8\], ({reg}[::r64::]))",
            R"(lea rsp, \[rsp-0x8\])",
        },
        std::vector<std::string>{R"(push ${reg})"});

    multimatches.emplace_back(

        "push via lea rsp, [rsp-0x8]; mov [rsp], reg",
        std::vector<std::string>{
            R"(lea rsp, \[rsp-0x8\])",
            R"(mov [::qword_ptr::]\[rsp\], ({reg}[::r64::]))",
        },
        std::vector<std::string>{R"(push ${reg})"});

    multimatches.emplace_back(

        "pop via lea rsp, [rsp+0x8]; mov reg, [rsp]",
        std::vector<std::string>{
            R"(lea rsp, \[rsp\+0x8\])",
            R"(mov ({reg}[::r64::]), [::qword_ptr::]\[rsp-0x8\])",
        },
        std::vector<std::string>{R"(pop ${reg})"});

    multimatches.emplace_back(

        "pop via mov reg, [rsp]",
        std::vector<std::string>{
            R"(mov ({reg}[::r64::]), [::qword_ptr::]\[rsp\])",
            R"(lea rsp, \[rsp\+0x8\])",
        },
        std::vector<std::string>{R"(pop ${reg})"});

    multimatches.emplace_back(

        "ret via lea rsp; jmp",
        std::vector<std::string>{
            R"(lea rsp, \[rsp\+0x8\])",
            R"(jmp [::qword::]\[rsp-0x8\])",
        },
        std::vector<std::string>{"retn"});
}
#endif

