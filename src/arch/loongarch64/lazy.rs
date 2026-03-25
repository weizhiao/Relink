pub(crate) const DYLIB_OFFSET: usize = 1;
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 0;

#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
        addi.d  $sp, $sp, -224
        st.d    $ra, $sp, 0
        st.d    $a0, $sp, 8
        st.d    $a1, $sp, 16
        st.d    $a2, $sp, 24
        st.d    $a3, $sp, 32
        st.d    $a4, $sp, 40
        st.d    $a5, $sp, 48
        st.d    $a6, $sp, 56
        st.d    $a7, $sp, 64
        st.d    $t0, $sp, 72
        st.d    $t1, $sp, 80
        // 16 bytes padding to align vr0 to 16 bytes (sp + 96)
        vst     $vr0, $sp, 96
        vst     $vr1, $sp, 112
        vst     $vr2, $sp, 128
        vst     $vr3, $sp, 144
        vst     $vr4, $sp, 160
        vst     $vr5, $sp, 176
        vst     $vr6, $sp, 192
        vst     $vr7, $sp, 208

        move    $a0, $t0
        srli.d  $a1, $t1, 3
        la.local $t2, {0}
        jirl    $ra, $t2, 0

        move    $t2, $a0

        ld.d    $ra, $sp, 0
        ld.d    $a0, $sp, 8
        ld.d    $a1, $sp, 16
        ld.d    $a2, $sp, 24
        ld.d    $a3, $sp, 32
        ld.d    $a4, $sp, 40
        ld.d    $a5, $sp, 48
        ld.d    $a6, $sp, 56
        ld.d    $a7, $sp, 64
        ld.d    $t0, $sp, 72
        ld.d    $t1, $sp, 80
        vld     $vr0, $sp, 96
        vld     $vr1, $sp, 112
        vld     $vr2, $sp, 128
        vld     $vr3, $sp, 144
        vld     $vr4, $sp, 160
        vld     $vr5, $sp, 176
        vld     $vr6, $sp, 192
        vld     $vr7, $sp, 208

        addi.d  $sp, $sp, 224

        jr      $t2
    ",
        sym crate::relocation::dl_fixup,
    )
}
