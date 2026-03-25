pub(crate) const DYLIB_OFFSET: usize = 1;
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 0;

#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
        // 保存整数参数寄存器
        // ra, a0-a7: 9 * 4 = 36 bytes
        // 栈帧总大小设为 112 字节以保持 16 字节对齐
        addi sp,sp,-112
        sw ra,0(sp)
        sw a0,4(sp)
        sw a1,8(sp)
        sw a2,12(sp)
        sw a3,16(sp)
        sw a4,20(sp)
        sw a5,24(sp)
        sw a6,28(sp)
        sw a7,32(sp)
        ",
        #[cfg(target_feature = "d")]
        "
        fsd fa0,40(sp)
        fsd fa1,48(sp)
        fsd fa2,56(sp)
        fsd fa3,64(sp)
        fsd fa4,72(sp)
        fsd fa5,80(sp)
        fsd fa6,88(sp)
        fsd fa7,96(sp)
        ",
        #[cfg(all(target_feature = "f", not(target_feature = "d")))]
        "
        fsw fa0,40(sp)
        fsw fa1,44(sp)
        fsw fa2,48(sp)
        fsw fa3,52(sp)
        fsw fa4,56(sp)
        fsw fa5,60(sp)
        fsw fa6,64(sp)
        fsw fa7,68(sp)
        ",
        "
        // 这两个是plt代码设置的
        mv a0,t0
        srli a1,t1,3
        // 调用重定位函数
        call {0}
        // 恢复参数寄存器
        mv t1,a0
        lw ra,0(sp)
        lw a0,4(sp)
        lw a1,8(sp)
        lw a2,12(sp)
        lw a3,16(sp)
        lw a4,20(sp)
        lw a5,24(sp)
        lw a6,28(sp)
        lw a7,32(sp)
        ",
        #[cfg(target_feature = "d")]
        "
        fld fa0,40(sp)
        fld fa1,48(sp)
        fld fa2,56(sp)
        fld fa3,64(sp)
        fld fa4,72(sp)
        fld fa5,80(sp)
        fld fa6,88(sp)
        fld fa7,96(sp)
        ",
        #[cfg(all(target_feature = "f", not(target_feature = "d")))]
        "
        flw fa0,40(sp)
        flw fa1,44(sp)
        flw fa2,48(sp)
        flw fa3,52(sp)
        flw fa4,56(sp)
        flw fa5,60(sp)
        flw fa6,64(sp)
        flw fa7,68(sp)
        ",
        "
        addi sp,sp,112
        // 执行真正的函数
        jr t1
        ",
        sym crate::relocation::dl_fixup,
    )
}
