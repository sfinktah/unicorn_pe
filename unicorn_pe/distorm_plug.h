#pragma once
int emu_disassemble(virtual_buffer_based_t& buffer, uintptr_t begin, uintptr_t end, const std::function<bool(FuncTailInsn)>& callback);

