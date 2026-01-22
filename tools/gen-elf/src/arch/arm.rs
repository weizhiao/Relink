pub(crate) fn generate_plt0_code() -> Vec<u8> {
    let mut code = vec![0; 20];

    // push    {lr}          ; (str lr, [sp, #-4]!)
    code[0..4].copy_from_slice(&[0x04, 0xe0, 0x2d, 0xe5]);

    // ldr     lr, [pc, #4]  ; 加载偏移量到 lr
    code[4..8].copy_from_slice(&[0x04, 0xe0, 0x9f, 0xe5]);

    // add     lr, pc, lr    ; lr = pc + offset (计算 GOT 地址)
    code[8..12].copy_from_slice(&[0x0e, 0xe0, 0x8f, 0xe0]);

    // ldr     pc, [lr, #8]! ; 跳转到 GOT[2], lr 更新为 GOT[1]
    code[12..16].copy_from_slice(&[0x08, 0xf0, 0xbe, 0xe5]);

    // .word 0x... (由 patch_plt0 填充)
    code
}

pub(crate) fn patch_plt0(
    plt_data: &mut [u8],
    plt0_off: usize,
    plt0_vaddr: u64,
    got_plt_vaddr: u64,
) {
    // pc 指向 .word 所在的地址 (即 plt0_vaddr + 16)
    let pc_val = plt0_vaddr + 16;
    let offset = (got_plt_vaddr as i64 - pc_val as i64) as u32;

    // 将计算出的偏移量写入到指令序列后的数据字中
    plt_data[plt0_off + 16..plt0_off + 20].copy_from_slice(&offset.to_le_bytes());
}

pub(crate) fn generate_plt_entry_code() -> Vec<u8> {
    let mut code = vec![0; 12];

    // 1. add ip, pc, #HIGH
    code[0..4].copy_from_slice(&[0x00, 0xc0, 0x8f, 0xe2]);
    // 2. add ip, ip, #MID
    code[4..8].copy_from_slice(&[0x00, 0xc0, 0x8c, 0xe2]);
    // 3. ldr pc, [ip, #LOW]!
    code[8..12].copy_from_slice(&[0x00, 0xf0, 0xbc, 0xe5]);

    code
}

pub(crate) fn patch_plt_entry(
    plt_data: &mut [u8],
    plt_entry_off: usize,
    plt_entry_vaddr: u64,
    target_got_vaddr: u64,
) {
    // 1. 计算总偏移量
    // 这里的基准是第一条指令执行时的 PC。
    // ARM 流水线中，执行第一条指令时，PC = plt_entry_vaddr + 8
    let pc = plt_entry_vaddr + 8;
    let offset = (target_got_vaddr as i64 - pc as i64) as u32;

    // 2. 拆分偏移量
    // 目标是：offset = Imm(High) + Imm(Mid) + Low_12

    // 步骤 A: 剥离 LDR 的 12 位偏移 (0..4095)
    let low_12 = offset & 0xfff;
    let residual = offset - low_12;

    // 步骤 B: 剩余部分 (residual) 需要用两条 ADD 指令表示。
    // ARM 的 ADD 立即数必须能表示为：8位值 循环右移 偶数位。
    // 在你的例子中 (0x66000) 正好是一个合法的立即数，所以一条 ADD 就能搞定，另一条填 0。

    // 简单的拆分策略：
    // 尝试直接编码 residual。如果成功，第二条 ADD 填 0。
    // 如果不行，尝试把 residual 拆成两部分 (这是一个复杂的位操作问题，
    // 这里为了适配 GCC 的行为，我们可以尝试按位拆分)。

    let (imm_high, imm_mid) = if let Some(enc) = encode_arm_imm(residual) {
        (0, enc) // 一条指令够用，比如 0x66000
    } else {
        // 简单回退策略：取最高有效位的掩码
        let high_part = residual & 0xFFF00000; // 这是一个粗略的假设
        let mid_part = residual - high_part;

        let enc_h = encode_arm_imm(high_part).expect("Failed to encode high part of PLT offset");
        let enc_m = encode_arm_imm(mid_part).expect("Failed to encode mid part of PLT offset");
        (enc_h, enc_m)
    };

    // 3. 写入指令

    // 指令 1: add ip, pc, #imm_high
    // 0xe28fc... 是 add ip, pc, ...
    let insn1 = 0xe28fc000 | imm_high;
    plt_data[plt_entry_off..plt_entry_off + 4].copy_from_slice(&insn1.to_le_bytes());

    // 指令 2: add ip, ip, #imm_mid
    // 0xe28cc... 是 add ip, ip, ...
    let insn2 = 0xe28cc000 | imm_mid;
    plt_data[plt_entry_off + 4..plt_entry_off + 8].copy_from_slice(&insn2.to_le_bytes());

    // 指令 3: ldr pc, [ip, #low_12]!
    // 0xe5bcf... 是 ldr pc, [ip, #...]!
    let insn3 = 0xe5bcf000 | low_12;
    plt_data[plt_entry_off + 8..plt_entry_off + 12].copy_from_slice(&insn3.to_le_bytes());
}

// 辅助函数：将 u32 编码为 ARM 立即数格式 (12位: 4位 rotate + 8位 imm)
fn encode_arm_imm(mut n: u32) -> Option<u32> {
    if n == 0 {
        return Some(0);
    }
    for r in 0..16 {
        // 尝试循环左移 (2*r)，看结果是否能放入 8 bits
        if n <= 0xFF {
            // 编码格式: rot 在 [11:8], imm 在 [7:0]
            // ARM 解码逻辑是: imm ROR (rot * 2)
            // 我们通过 rotate_left(2*r) 找到了 imm，使得 n.rotate_left(2*r) = imm
            // 即 n = imm.rotate_right(2*r) = imm ROR (2*r)
            // 所以 rot 应该等于 r
            let rot_code = r;
            return Some(n | (rot_code << 8));
        }
        n = n.rotate_left(2);
    }
    None
}

pub(crate) fn generate_helper_code() -> Vec<u8> {
    // 一个简单的跳转指令
    let mut code = vec![0; 4];
    // b <offset> (Placeholder)
    code[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0xea]);
    code
}

pub(crate) fn patch_helper(
    text_data: &mut [u8],
    helper_text_off: usize,
    helper_vaddr: u64,
    target_plt_vaddr: u64,
) {
    // b is at helper_vaddr. PC = helper_vaddr + 8
    let off = (target_plt_vaddr as i64 - (helper_vaddr + 8) as i64) / 4;
    let insn = 0xea000000 | ((off & 0x00ffffff) as u32);
    text_data[helper_text_off..helper_text_off + 4].copy_from_slice(&insn.to_le_bytes());
}

pub(crate) fn get_ifunc_resolver_code() -> Vec<u8> {
    let mut code = vec![0; 16];
    // ldr r0, [pc, #4]
    code[0..4].copy_from_slice(&[0x04, 0x00, 0x9f, 0xe5]);
    // add r0, pc, r0
    code[4..8].copy_from_slice(&[0x00, 0x00, 0x8f, 0xe0]);
    // bx lr
    code[8..12].copy_from_slice(&[0x1e, 0xff, 0x2f, 0xe1]);
    // <target_offset (4 bytes)>
    code
}

pub(crate) fn patch_ifunc_resolver(
    text_data: &mut [u8],
    offset: usize,
    resolver_vaddr: u64,
    target_vaddr: u64,
) {
    // pc at the add instruction (offset + 4) is resolver_vaddr + 4 + 8 = resolver_vaddr + 12
    let pc = resolver_vaddr + 12;
    let off = (target_vaddr as i64 - pc as i64) as i32;
    text_data[offset + 12..offset + 16].copy_from_slice(&off.to_le_bytes());
}

pub(crate) fn generate_tls_helper_code() -> Vec<u8> {
    let mut code = vec![0; 32];
    // Fill with NOPs (mov r0, r0 -> 0xe1a00000)
    for i in (0..32).step_by(4) {
        code[i..i + 4].copy_from_slice(&[0x00, 0x00, 0xa0, 0xe1]);
    }

    // 0x00: push {r4, lr} (to keep stack 8-byte aligned)
    code[0..4].copy_from_slice(&[0x10, 0x40, 0x2d, 0xe9]);

    // 0x10: pop {r4, pc} (restore r4 and return)
    code[16..20].copy_from_slice(&[0x10, 0x80, 0xbd, 0xe8]);

    code
}

pub(crate) fn patch_tls_tester(
    text_data: &mut [u8],
    offset: usize,
    helper_vaddr: u64,
    reloc_vaddr: u64,
    tls_get_addr_vaddr: u64,
) {
    // 0x04: ldr r0, [pc, #12] (load offset to GOT slot from offset 24)
    // PC points to helper_vaddr + 4 + 8 = helper_vaddr + 12
    // Data is at helper_vaddr + 24. Offset = 24 - 12 = 12.
    text_data[offset + 4..offset + 8].copy_from_slice(&[0x0c, 0x00, 0x9f, 0xe5]);

    // 0x08: add r0, pc, r0
    // PC points to helper_vaddr + 8 + 8 = helper_vaddr + 16
    // r0 will be (reloc_vaddr - (helper_vaddr + 16)) + (helper_vaddr + 16) = reloc_vaddr
    text_data[offset + 8..offset + 12].copy_from_slice(&[0x00, 0x00, 0x8f, 0xe0]);

    // 0x0c: bl __tls_get_addr
    // PC points to helper_vaddr + 12 + 8 = helper_vaddr + 20
    let bl_off = (tls_get_addr_vaddr as i64 - (helper_vaddr as i64 + 20)) >> 2;
    let bl = 0xeb000000u32 | (bl_off as u32 & 0x00ffffff);
    text_data[offset + 12..offset + 16].copy_from_slice(&bl.to_le_bytes());

    // Data at offset 24: reloc_vaddr - (helper_vaddr + 16)
    let data_val = (reloc_vaddr as i64 - (helper_vaddr as i64 + 16)) as i32;
    text_data[offset + 24..offset + 28].copy_from_slice(&data_val.to_le_bytes());
}
