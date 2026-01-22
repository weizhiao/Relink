pub(crate) fn generate_plt0_code() -> Vec<u8> {
    let mut plt_data = vec![];

    // push dword [ebx+4] (link_map)
    plt_data.extend_from_slice(&[0xff, 0xb3, 0x04, 0x00, 0x00, 0x00]);

    // jmp dword [ebx+8] (_dl_runtime_resolve)
    plt_data.extend_from_slice(&[0xff, 0xa3, 0x08, 0x00, 0x00, 0x00]);

    plt_data.resize(16, 0x90);
    plt_data
}

pub(crate) fn generate_plt_entry_code(reloc_idx: u32, plt_entry_offset: u64) -> Vec<u8> {
    let mut plt_data = vec![];
    let reloc_offset = reloc_idx * 8; // x86 Rel entry size is 8

    // jmp dword [ebx + offset]
    plt_data.extend_from_slice(&[0xff, 0xa3, 0, 0, 0, 0]);

    // push reloc_offset
    plt_data.extend_from_slice(&[0x68]);
    plt_data.extend_from_slice(&reloc_offset.to_le_bytes());

    // jmp PLT[0]
    plt_data.extend_from_slice(&[0xe9]);
    // The jmp instruction is at offset 11 (6 + 5). Next instruction is at offset 16.
    // PLT0 is at -plt_entry_offset.
    // Offset = target - next = -plt_entry_offset - 16
    let plt0_offset = -(plt_entry_offset as i32 + 16);
    plt_data.extend_from_slice(&plt0_offset.to_le_bytes());

    plt_data.resize(16, 0x90);
    plt_data
}

pub(crate) fn patch_plt_entry(
    plt_data: &mut [u8],
    plt_entry_off: usize,
    target_got_vaddr: u64,
    got_vaddr: u64,
) {
    let offset = (target_got_vaddr - got_vaddr) as u32;
    plt_data[plt_entry_off + 2..plt_entry_off + 6].copy_from_slice(&offset.to_le_bytes());
}

pub(crate) fn generate_helper_code() -> Vec<u8> {
    // call 1f; 1: pop ebx; add ebx, _GLOBAL_OFFSET_TABLE_; jmp target@PLT
    let mut code = vec![0x90; 32];
    // call 1f (offset 5)
    code[0] = 0xe8;
    code[1] = 0x00;
    code[2] = 0x00;
    code[3] = 0x00;
    code[4] = 0x00;
    // pop ebx
    code[5] = 0x5b;
    // add ebx, imm32
    code[6] = 0x81;
    code[7] = 0xc3;
    // jmp rel32
    code[12] = 0xe9;
    code
}

pub(crate) fn patch_helper(
    text_data: &mut [u8],
    helper_text_off: usize,
    helper_vaddr: u64,
    target_plt_vaddr: u64,
    got_vaddr: u64,
) {
    // Patch GOT offset for ebx
    // ebx = helper_vaddr + 5 after pop
    let got_off = (got_vaddr as i64 - (helper_vaddr + 5) as i64) as i32;
    text_data[helper_text_off + 8..helper_text_off + 12].copy_from_slice(&got_off.to_le_bytes());

    // Patch PLT jmp
    // jmp rel32 is at helper_vaddr + 12. Next instruction is at helper_vaddr + 17.
    let rel_off = (target_plt_vaddr as i64 - (helper_vaddr + 17) as i64) as i32;
    text_data[helper_text_off + 13..helper_text_off + 17].copy_from_slice(&rel_off.to_le_bytes());
}

pub(crate) fn get_ifunc_resolver_code() -> Vec<u8> {
    // call 1f; 1: pop eax; add eax, imm32; ret
    let mut code = vec![0x90; 16];
    // call 1f (offset 5)
    code[0] = 0xe8;
    code[1] = 0x00;
    code[2] = 0x00;
    code[3] = 0x00;
    code[4] = 0x00;
    // pop eax
    code[5] = 0x58;
    // add eax, imm32
    code[6] = 0x05;
    // ret
    code[11] = 0xc3;
    code
}

pub(crate) fn patch_ifunc_resolver(
    text_data: &mut [u8],
    offset: usize,
    resolver_vaddr: u64,
    target_vaddr: u64,
) {
    // eax = resolver_vaddr + 5 after pop
    // we want eax = target_vaddr
    // so imm32 = target_vaddr - (resolver_vaddr + 5)
    let imm32 = (target_vaddr as i64 - (resolver_vaddr + 5) as i64) as i32;
    text_data[offset + 7..offset + 11].copy_from_slice(&imm32.to_le_bytes());
}

pub(crate) fn generate_tls_helper_code() -> Vec<u8> {
    let mut code = vec![0x90; 64];

    // 0x00: push ebp; mov ebp, esp
    code[0] = 0x55;
    code[1] = 0x89; code[2] = 0xe5;

    // 0x03: push ebx
    code[3] = 0x53;

    // 0x04: call +0 (to get EIP)
    code[4] = 0xe8;
    code[5] = 0x00; code[6] = 0x00; code[7] = 0x00; code[8] = 0x00;

    // 0x09: pop ebx (ebx = helper_vaddr + 9)
    code[9] = 0x5b;

    // 0x0a: add ebx, imm32 (offset to GOT)
    code[10] = 0x81; code[11] = 0xc3;

    // 0x10: lea eax, [ebx + imm32] (offset to reloc_vaddr from GOT)
    code[16] = 0x8d; code[17] = 0x83;

    // 0x16: push eax (argument for __tls_get_addr)
    code[22] = 0x50;

    // 0x17: call rel32 (patch to __tls_get_addr@plt)
    code[23] = 0xe8;

    // 0x1c: add esp, 4 (cleanup push)
    code[28] = 0x83; code[29] = 0xc4; code[30] = 0x04;

    // 0x1f: pop ebx; pop ebp; ret
    code[31] = 0x5b;
    code[32] = 0x5d;
    code[33] = 0xc3;

    code
}

pub(crate) fn patch_tls_tester(
    text_data: &mut [u8],
    offset: usize,
    helper_vaddr: u64,
    reloc_vaddr: u64,
    tls_get_addr_vaddr: u64,
    got_vaddr: u64,
) {
    // 0x0a: add ebx, imm32
    // ebx is helper_vaddr + 9 after pop.
    let got_off = (got_vaddr as i64 - (helper_vaddr + 9) as i64) as i32;
    text_data[offset + 12..offset + 16].copy_from_slice(&got_off.to_le_bytes());

    // 0x10: lea eax, [ebx + imm32]
    // ebx is now got_vaddr. We want eax = reloc_vaddr.
    let reloc_off = (reloc_vaddr as i64 - got_vaddr as i64) as i32;
    text_data[offset + 18..offset + 22].copy_from_slice(&reloc_off.to_le_bytes());

    // 0x17: call rel32
    // Next instruction is at helper_vaddr + 28.
    let rel_off = (tls_get_addr_vaddr as i64 - (helper_vaddr + 28) as i64) as i32;
    text_data[offset + 24..offset + 28].copy_from_slice(&rel_off.to_le_bytes());
}
