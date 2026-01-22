pub(crate) fn generate_plt0_code() -> Vec<u8> {
    vec![0; 32]
}

fn encode_imm26(imm: i32) -> u32 {
    let imm = imm as u32;
    ((imm & 0xffff) << 10) | ((imm >> 16) & 0x3ff)
}

pub(crate) fn patch_plt0(
    plt_data: &mut [u8],
    plt0_off: usize,
    plt0_vaddr: u64,
    got_plt_vaddr: u64,
) {
    let pc = plt0_vaddr;
    let target_got0 = got_plt_vaddr; // GOT[0] is resolver
    // let _target_got1 = got_vaddr + 8; // GOT[1] is link_map

    let off = target_got0 as i64 - pc as i64;

    // 1. pcaddi $t2, imm20
    let imm20 = (off >> 2) as i32;
    let pcaddi = 0x18000000u32 | (14 << 0) | ((imm20 as u32 & 0xfffff) << 5); // $t2($r14) = PC + offset

    // 2. ld.d $t0, $t2, 8  (GOT[1] -> link_map, load into $r12)
    let ld_linkmap = 0x28c00000u32 | (12 << 0) | (14 << 5) | (8 << 10);

    // 3. ld.d $t2, $t2, 0  (GOT[0] -> resolver, load into $r14)
    let ld_resolver = 0x28c00000u32 | (14 << 0) | (14 << 5) | (0 << 10);

    // 4. jr $t2 (Jump to resolver)
    let jr = 0x4c000000u32 | (0 << 0) | (14 << 5) | (0 << 10);

    plt_data[plt0_off..plt0_off + 4].copy_from_slice(&pcaddi.to_le_bytes());
    plt_data[plt0_off + 4..plt0_off + 8].copy_from_slice(&ld_linkmap.to_le_bytes());
    plt_data[plt0_off + 8..plt0_off + 12].copy_from_slice(&ld_resolver.to_le_bytes());
    plt_data[plt0_off + 12..plt0_off + 16].copy_from_slice(&jr.to_le_bytes());
}

pub(crate) fn generate_plt_entry_code(reloc_idx: u32, plt_entry_offset: u64) -> Vec<u8> {
    let mut code = vec![0; 32];

    // LoongArch NOP: andi $r0, $r0, 0 => 0x03400000
    let nop = 0x03400000u32;
    code[12..16].copy_from_slice(&nop.to_le_bytes());

    // li.d $t1, reloc_idx * 8 (Load reloc index for lazy binding)
    let reloc_val = reloc_idx * 8;
    let li = 0x02800000 | (13 << 0) | ((reloc_val & 0xfff) << 10); // $t1($r13)

    // b PLT0 (Jump to PLT0 resolver stub)
    // 偏移量计算：PLT0 is usually at the start of section.
    // Lazy path starts at offset 20. So jump back `plt_entry_offset + 20`.
    let plt0_off = -(plt_entry_offset as i32 + 20);
    let b_imm = plt0_off >> 2;
    let b = 0x50000000 | encode_imm26(b_imm);

    code[16..20].copy_from_slice(&li.to_le_bytes());
    code[20..24].copy_from_slice(&b.to_le_bytes());
    code
}

pub(crate) fn patch_plt_entry(
    plt_data: &mut [u8],
    plt_entry_off: usize,
    plt_entry_vaddr: u64,
    target_got_vaddr: u64,
) {
    let pc = plt_entry_vaddr;
    let off = target_got_vaddr as i64 - pc as i64;

    let imm20 = (off >> 2) as i32;
    let pcaddi = 0x18000000u32 | (14 << 0) | ((imm20 as u32 & 0xfffff) << 5); // pcaddi $t2, imm

    // ld.d $t1, $t2, 0
    // 注意：这里加载到 $t1 ($r13) 是用来跳转的
    let ld = 0x28c00000u32 | (13 << 0) | (14 << 5) | (0 << 10);

    // jr $t1
    let jirl = 0x4c000000u32 | (0 << 0) | (13 << 5) | (0 << 10);

    plt_data[plt_entry_off..plt_entry_off + 4].copy_from_slice(&pcaddi.to_le_bytes());
    plt_data[plt_entry_off + 4..plt_entry_off + 8].copy_from_slice(&ld.to_le_bytes());
    plt_data[plt_entry_off + 8..plt_entry_off + 12].copy_from_slice(&jirl.to_le_bytes());

    // 偏移 12-16 保持原样，由 generate_plt_entry_code 填充 NOP
}

pub(crate) fn generate_helper_code() -> Vec<u8> {
    // b <offset>
    vec![0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00]
}

pub(crate) fn patch_helper(
    text_data: &mut [u8],
    helper_text_off: usize,
    helper_vaddr: u64,
    target_plt_vaddr: u64,
) {
    let off = (target_plt_vaddr as i64 - helper_vaddr as i64) / 4;
    let insn = 0x50000000 | encode_imm26(off as i32);
    text_data[helper_text_off..helper_text_off + 4].copy_from_slice(&insn.to_le_bytes());
}

pub(crate) fn get_ifunc_resolver_code() -> Vec<u8> {
    // 0: pcalau12i $a0, %hi20
    // 4: addi.d $a0, $a0, %lo12
    // 8: jirl $zero, $ra, 0 (Return)
    // 12: nop
    let mut code = vec![0; 16];

    // pcalau12i $a0, 0 -> 0x1a000004
    code[0..4].copy_from_slice(&[0x04, 0x00, 0x00, 0x1a]);

    // addi.d $a0, $a0, 0 -> 0x02c00084
    code[4..8].copy_from_slice(&[0x84, 0x00, 0xc0, 0x02]);

    // jirl $zero, $ra, 0 -> 0x4c000020
    code[8..12].copy_from_slice(&[0x20, 0x00, 0x00, 0x4c]);

    // nop -> 0x03400000
    code[12..16].copy_from_slice(&[0x00, 0x00, 0x40, 0x03]);

    code
}

pub(crate) fn patch_ifunc_resolver(
    text_data: &mut [u8],
    offset: usize,
    resolver_vaddr: u64,
    target_vaddr: u64,
) {
    let pc = resolver_vaddr;
    // LoongArch pcalau12i + addi.d 组合计算绝对地址
    let hi = (target_vaddr as i64 - (pc as i64 & !0xfff) + 0x800) >> 12;
    let lo = target_vaddr as i64 & 0xfff;

    let pcalau12i = 0x1a000000u32 | (4 << 0) | ((hi as u32 & 0xfffff) << 5);
    let addi = 0x02c00000u32 | (4 << 0) | (4 << 5) | ((lo as u32 & 0xfff) << 10);

    text_data[offset..offset + 4].copy_from_slice(&pcalau12i.to_le_bytes());
    text_data[offset + 4..offset + 8].copy_from_slice(&addi.to_le_bytes());
}

pub(crate) fn generate_tls_helper_code() -> Vec<u8> {
    let mut code = vec![0; 40];
    // Fill with NOPs (0x03400000)
    for i in (0..40).step_by(4) {
        code[i..i + 4].copy_from_slice(&[0x00, 0x00, 0x40, 0x03]);
    }

    // 0x00: addi.d $sp, $sp, -16
    let addi_sp_neg = 0x02c00000u32 | (3 << 0) | (3 << 5) | ((-16i32 as u32 & 0xfff) << 10);
    code[0..4].copy_from_slice(&addi_sp_neg.to_le_bytes());

    // 0x04: st.d $ra, $sp, 8
    let st_ra = 0x29c00000u32 | (1 << 0) | (3 << 5) | (8 << 10);
    code[4..8].copy_from_slice(&st_ra.to_le_bytes());

    // 0x18: ld.d $ra, $sp, 8
    let ld_ra = 0x28c00000u32 | (1 << 0) | (3 << 5) | (8 << 10);
    code[24..28].copy_from_slice(&ld_ra.to_le_bytes());

    // 0x1c: addi.d $sp, $sp, 16
    let addi_sp_pos = 0x02c00000u32 | (3 << 0) | (3 << 5) | (16 << 10);
    code[28..32].copy_from_slice(&addi_sp_pos.to_le_bytes());

    // 0x20: jirl $zero, $ra, 0 (ret)
    let ret = 0x4c000000u32 | (0 << 0) | (1 << 5) | (0 << 10);
    code[32..36].copy_from_slice(&ret.to_le_bytes());

    code
}

pub(crate) fn patch_tls_tester(
    text_data: &mut [u8],
    offset: usize,
    helper_vaddr: u64,
    reloc_vaddr: u64,
    tls_get_addr_vaddr: u64,
) {
    // 0x08: pcalau12i $a0, %gd_hi20(reloc_vaddr)
    // 0x0c: addi.d $a0, $a0, %gd_lo12(reloc_vaddr)
    let pc = helper_vaddr + 8;
    let hi = (reloc_vaddr as i64 - (pc as i64 & !0xfff) + 0x800) >> 12;
    let lo = reloc_vaddr & 0xfff;

    let pcalau12i_a0 = 0x1a000000u32 | (4 << 0) | ((hi as u32 & 0xfffff) << 5);
    let addi_a0 = 0x02c00000u32 | (4 << 0) | (4 << 5) | ((lo as u32 & 0xfff) << 10);

    text_data[offset + 8..offset + 12].copy_from_slice(&pcalau12i_a0.to_le_bytes());
    text_data[offset + 12..offset + 16].copy_from_slice(&addi_a0.to_le_bytes());

    // 0x10: bl __tls_get_addr
    let bl_off = (tls_get_addr_vaddr as i64 - (helper_vaddr as i64 + 16)) >> 2;
    let bl = 0x54000000u32 | encode_imm26(bl_off as i32);
    text_data[offset + 16..offset + 20].copy_from_slice(&bl.to_le_bytes());
}
