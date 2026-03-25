pub(crate) const DYLIB_OFFSET: usize = 1;
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 2;

#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
    // 保存调用者保存的寄存器
    push eax
    push ecx
    push edx

    // 此时栈布局:
    // [esp]      : edx
    // [esp + 4]  : ecx
    // [esp + 8]  : eax
    // [esp + 12] : link_map (由 PLT0 压入)
    // [esp + 16] : reloc_offset (由 PLT 条目压入)
    // [esp + 20] : 返回地址

    // 准备 dl_fixup(link_map, reloc_idx) 的参数
    // reloc_idx = reloc_offset / 8 (x86 Rel 条目大小为 8)
    mov eax, [esp + 16]
    shr eax, 3
    
    push eax         // 参数 2: reloc_idx
    push dword ptr [esp + 16]  // 参数 1: link_map (原本在 +12，现在因为 push eax 变成了 +16)

    call {0}

    // 清理参数
    add esp, 8

    // eax 现在包含解析后的地址。将其存入栈中原本 reloc_offset 的位置。
    mov [esp + 16], eax

    // 恢复寄存器
    pop edx
    pop ecx
    pop eax

    // 跳过 link_map，此时栈顶是解析后的地址
    add esp, 4

    // 弹出解析后的地址并跳转
    ret
    ",
        sym crate::relocation::dl_fixup,
    )
}
