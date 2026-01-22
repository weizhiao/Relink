pub(crate) fn generate_plt0_code() -> Vec<u8> {
    let mut code = vec![0; 32];

    // 0x00: stp x16, x30, [sp, #-16]!
    code[0..4].copy_from_slice(&[0xf0, 0x7b, 0xbf, 0xa9]);

    // 0x04: adrp x16, ... (在 patch 中生成)
    // 0x08: ldr  x17, ... (在 patch 中生成)
    // 0x0c: add  x16, ... (在 patch 中生成)

    // 0x10: br x17 (GCC 布局中跳转指令前移了)
    code[16..20].copy_from_slice(&[0x20, 0x02, 0x1f, 0xd6]);

    // 0x14, 0x18, 0x1c: NOPs
    code[20..24].copy_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
    code[24..28].copy_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
    code[28..32].copy_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);

    code
}

pub(crate) fn patch_plt0(
    plt_data: &mut [u8],
    plt0_off: usize,
    plt0_vaddr: u64,
    got_plt_vaddr: u64,
) {
    let pc = plt0_vaddr + 4; // adrp 位于 PLT0+4
    // GOT[2] = Resolver Address.
    let got_resolver_offset = (got_plt_vaddr & 0xfff) as u32 + 16;

    // adrp x16, Page(GOT)
    let adrp = encode_adrp(16, pc, got_plt_vaddr);
    // ldr x17, [x16, #offset]
    let ldr_x17 = encode_ldr_imm12(17, 16, got_resolver_offset);
    // add x16, x16, #offset
    let add_x16 = encode_add_imm12(16, 16, got_resolver_offset);

    // Offset 4: adrp x16, ...
    plt_data[plt0_off + 4..plt0_off + 8].copy_from_slice(&adrp.to_le_bytes());

    // Offset 8: ldr x17, [x16, #...]
    plt_data[plt0_off + 8..plt0_off + 12].copy_from_slice(&ldr_x17.to_le_bytes());

    // Offset 12: add x16, x16, #...
    plt_data[plt0_off + 12..plt0_off + 16].copy_from_slice(&add_x16.to_le_bytes());
}

pub(crate) fn generate_plt_entry_code() -> Vec<u8> {
    let mut code = vec![0; 16];
    // adrp x16, ...
    // ldr x17, [x16, #...]
    // add x16, x16, #...
    // br x17
    // (reloc_idx is not used in direct jump, but needed for lazy resolution)
    code[12..16].copy_from_slice(&[0x20, 0x02, 0x1f, 0xd6]);
    code
}

pub(crate) fn patch_plt_entry(
    plt_data: &mut [u8],
    plt_entry_off: usize,
    plt_entry_vaddr: u64,
    target_got_vaddr: u64,
) {
    let pc = plt_entry_vaddr;
    let target_page_offset = (target_got_vaddr & 0xfff) as u32;

    // adrp x16, Page(TargetGOT)
    let adrp = encode_adrp(16, pc, target_got_vaddr);

    // ldr x17, [x16, Offset]
    let ldr = encode_ldr_imm12(17, 16, target_page_offset);

    // add x16, x16, Offset
    let add = encode_add_imm12(16, 16, target_page_offset);

    plt_data[plt_entry_off..plt_entry_off + 4].copy_from_slice(&adrp.to_le_bytes());
    plt_data[plt_entry_off + 4..plt_entry_off + 8].copy_from_slice(&ldr.to_le_bytes());
    plt_data[plt_entry_off + 8..plt_entry_off + 12].copy_from_slice(&add.to_le_bytes());
}

fn encode_adrp(rd: u32, pc: u64, target: u64) -> u32 {
    let pc_page = pc >> 12;
    let target_page = target >> 12;
    let offset = (target_page as i64 - pc_page as i64) as u32;
    let immlo = offset & 3;
    let immhi = (offset >> 2) & 0x7ffff;
    0x90000000 | (immlo << 29) | (immhi << 5) | rd
}

fn encode_ldr_imm12(rt: u32, rn: u32, imm: u32) -> u32 {
    // LDR (immediate) 64-bit: 0xf9400000 | (imm12 >> 3) << 10 | rn << 5 | rt
    let imm12 = imm >> 3;
    0xf9400000 | (imm12 << 10) | (rn << 5) | rt
}

fn encode_add_imm12(rd: u32, rn: u32, imm: u32) -> u32 {
    // ADD (immediate) 64-bit: 0x91000000 | imm12 << 10 | rn << 5 | rd
    0x91000000 | (imm << 10) | (rn << 5) | rd
}

pub(crate) fn generate_helper_code() -> Vec<u8> {
    // 一个简单的跳转指令，预留空间给 patch_helper 来填充
    vec![0; 8]
}

pub(crate) fn patch_helper(
    text_data: &mut [u8],
    helper_text_off: usize,
    helper_vaddr: u64,
    target_plt_vaddr: u64,
) {
    let pc = helper_vaddr;

    // 计算相对偏移
    let off = (target_plt_vaddr as i64 - pc as i64) / 4;

    // 生成 b 指令 (26-bit immediate)
    // B: 0x14000000 | (imm26 & 0x03ffffff)
    let insn = 0x14000000 | ((off & 0x03ffffff) as u32);

    text_data[helper_text_off..helper_text_off + 4].copy_from_slice(&insn.to_le_bytes());
}

pub(crate) fn get_ifunc_resolver_code() -> Vec<u8> {
    let mut code = vec![0; 16];
    // adrp x0, .
    code[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x90]);
    // add x0, x0, #0
    code[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x91]);
    // ret
    code[8..12].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
    code
}

pub(crate) fn patch_ifunc_resolver(
    text_data: &mut [u8],
    offset: usize,
    resolver_vaddr: u64,
    target_vaddr: u64,
) {
    let pc = resolver_vaddr;
    let target = target_vaddr;

    // adrp x0, target
    let adrp = encode_adrp(0, pc, target);
    text_data[offset..offset + 4].copy_from_slice(&adrp.to_le_bytes());

    // add x0, x0, :lo12:target
    let add = encode_add_imm(0, 0, (target & 0xfff) as u32);
    text_data[offset + 4..offset + 8].copy_from_slice(&add.to_le_bytes());
}

pub(crate) fn generate_tls_helper_code() -> Vec<u8> {
    let mut code = vec![0; 32];
    // Fill with NOPs (0xd503201f)
    for i in (0..32).step_by(4) {
        code[i..i + 4].copy_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
    }

    // 0x00: stp x29, x30, [sp, #-16]!
    code[0..4].copy_from_slice(&[0xfd, 0x7b, 0xbf, 0xa9]);
    // 0x04: mov x29, sp
    code[4..8].copy_from_slice(&[0xfd, 0x03, 0x00, 0x91]);

    // 0x14: ldp x29, x30, [sp], #16
    code[20..24].copy_from_slice(&[0xfd, 0x7b, 0xc1, 0xa8]);
    // 0x18: ret
    code[24..28].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);

    code
}

pub(crate) fn patch_tls_tester(
    text_data: &mut [u8],
    offset: usize,
    helper_vaddr: u64,
    reloc_vaddr: u64,
    tls_get_addr_vaddr: u64,
) {
    // 0x08: adrp x0, Page(RelocVAddr)
    let adrp = encode_adrp(0, helper_vaddr + 8, reloc_vaddr);
    text_data[offset + 8..offset + 12].copy_from_slice(&adrp.to_le_bytes());

    // 0x0c: add x0, x0, :lo12:reloc_vaddr
    let add = encode_add_imm12(0, 0, (reloc_vaddr & 0xfff) as u32);
    text_data[offset + 12..offset + 16].copy_from_slice(&add.to_le_bytes());

    // 0x10: bl __tls_get_addr
    let bl = encode_bl(helper_vaddr + 16, tls_get_addr_vaddr);
    text_data[offset + 16..offset + 20].copy_from_slice(&bl.to_le_bytes());
}

fn encode_bl(pc: u64, target: u64) -> u32 {
    let offset = (target as i64 - pc as i64) / 4;
    0x94000000 | (offset as u32 & 0x03ffffff)
}

fn encode_add_imm(rd: u32, rn: u32, imm: u32) -> u32 {
    0x91000000 | (imm << 10) | (rn << 5) | rd
}
