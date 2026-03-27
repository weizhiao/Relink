#![allow(dead_code)]

#[cfg(feature = "tls")]
use std::{
    sync::{Arc, Barrier},
    thread,
};

use elf_loader::arch::{
    REL_COPY, REL_GOT, REL_IRELATIVE, REL_JUMP_SLOT, REL_RELATIVE, REL_SYMBOLIC,
};
#[cfg(feature = "tls")]
use elf_loader::arch::{REL_DTPMOD, REL_DTPOFF};
use gen_elf::SectionKind;

use super::fixture::{BindingScenario, FLOAT_TOLERANCE, IFUNC_RESOLVER_OFFSET};
use crate::support::host_symbols::{
    COPY_VAR_NAME, EXTERNAL_FUNC_NAME, EXTERNAL_FUNC_NAME2, EXTERNAL_TLS_NAME, EXTERNAL_TLS_NAME2,
    EXTERNAL_VAR_NAME, LOCAL_VAR_NAME,
};

fn assert_close_f64(actual: f64, expected: f64, context: &str) {
    assert!(
        (actual - expected).abs() < FLOAT_TOLERANCE,
        "{context} mismatch: expected {expected}, got {actual}"
    );
}

impl BindingScenario {
    pub(crate) fn assert_single_dependency(&self) {
        assert_eq!(
            self.loaded_dylib().deps().len(),
            1,
            "expected one retained dependency"
        );
    }

    pub(crate) fn assert_plt_helpers_work(&self) {
        let (_, expected) = self.expected_external_call_result();
        assert_close_f64(
            self.call_plt_helper(EXTERNAL_FUNC_NAME),
            expected,
            EXTERNAL_FUNC_NAME,
        );
        assert_close_f64(
            self.call_plt_helper(EXTERNAL_FUNC_NAME2),
            expected,
            EXTERNAL_FUNC_NAME2,
        );
    }

    fn assert_jump_slot_value(&self, symbol_name: &str, expected: u64) {
        let relocation = self.relocation_for_symbol(REL_JUMP_SLOT, symbol_name);
        let actual = self.slot_word(relocation);
        assert_eq!(actual, expected, "jump slot mismatch for {symbol_name}");
    }

    pub(crate) fn assert_eager_jump_slots(&self) {
        let external_addr = self.host_symbol_address(EXTERNAL_FUNC_NAME);
        assert!(
            !self.binding_kind().is_lazy(),
            "expected eager binding mode"
        );
        self.assert_jump_slot_value(EXTERNAL_FUNC_NAME, external_addr);
        self.assert_jump_slot_value(EXTERNAL_FUNC_NAME2, external_addr);
    }

    #[cfg(feature = "lazy-binding")]
    pub(crate) fn assert_lazy_jump_slots(&self) {
        let external_addr = self.host_symbol_address(EXTERNAL_FUNC_NAME);
        let first_slot = self.relocation_for_symbol(REL_JUMP_SLOT, EXTERNAL_FUNC_NAME);
        let second_slot = self.relocation_for_symbol(REL_JUMP_SLOT, EXTERNAL_FUNC_NAME2);

        assert!(self.binding_kind().is_lazy(), "expected lazy binding mode");
        let first_before = self.slot_word(first_slot);
        let second_before = self.slot_word(second_slot);
        assert_ne!(first_before, external_addr, "slot should start unresolved");
        assert_ne!(second_before, external_addr, "slot should start unresolved");

        let (_, expected) = self.expected_external_call_result();
        assert_close_f64(
            self.call_plt_helper(EXTERNAL_FUNC_NAME),
            expected,
            EXTERNAL_FUNC_NAME,
        );
        assert_eq!(self.slot_word(first_slot), external_addr);
        assert_eq!(
            self.slot_word(second_slot),
            second_before,
            "unrelated slot should stay unresolved"
        );

        assert_close_f64(
            self.call_plt_helper(EXTERNAL_FUNC_NAME2),
            expected,
            EXTERNAL_FUNC_NAME2,
        );
        assert_eq!(
            self.slot_word(first_slot),
            external_addr,
            "resolved slot should stay bound"
        );
        assert_eq!(self.slot_word(second_slot), external_addr);

        assert_close_f64(
            self.call_plt_helper(EXTERNAL_FUNC_NAME),
            expected,
            EXTERNAL_FUNC_NAME,
        );
        assert_eq!(
            self.slot_word(first_slot),
            external_addr,
            "repeated call should reuse resolved target"
        );
    }

    pub(crate) fn assert_non_plt_relocations(&self) {
        let got_relocation = self.relocation_for_symbol(REL_GOT, EXTERNAL_VAR_NAME);
        assert_eq!(got_relocation.section, SectionKind::Got);
        assert_eq!(
            self.slot_word(got_relocation),
            self.host_symbol_address(EXTERNAL_VAR_NAME)
        );

        let symbolic_relocation = self.relocation_for_symbol(REL_SYMBOLIC, LOCAL_VAR_NAME);
        let local_addr = self
            .loaded_symbol_address(LOCAL_VAR_NAME)
            .expect("missing local symbol");
        assert_eq!(
            self.slot_word(symbolic_relocation),
            local_addr.wrapping_add(symbolic_relocation.addend as u64),
            "REL_SYMBOLIC mismatch for {LOCAL_VAR_NAME}"
        );

        let copy_relocation = self.relocation_for_symbol(REL_COPY, COPY_VAR_NAME);
        assert_eq!(copy_relocation.section, SectionKind::Data);
        unsafe {
            let src = self
                .helper_dylib()
                .get::<u8>(COPY_VAR_NAME)
                .expect("missing copy source")
                .into_raw();
            let dst = self.slot_address(copy_relocation) as *const u8;
            assert_eq!(
                std::slice::from_raw_parts(src as *const u8, copy_relocation.sym_size as usize),
                std::slice::from_raw_parts(dst, copy_relocation.sym_size as usize),
                "REL_COPY mismatch for {COPY_VAR_NAME}"
            );
        }
    }

    #[cfg(feature = "tls")]
    pub(crate) fn assert_tls_relocations(&self) {
        let tls_mod_id = self
            .helper_dylib()
            .tls_mod_id()
            .expect("missing TLS mod id") as u64;

        for symbol_name in [EXTERNAL_TLS_NAME, EXTERNAL_TLS_NAME2] {
            let dtpmod = self.relocation_for_symbol(REL_DTPMOD, symbol_name);
            assert_eq!(dtpmod.section, SectionKind::Got);
            assert_eq!(
                self.slot_word(dtpmod),
                tls_mod_id,
                "REL_DTPMOD mismatch for {symbol_name}"
            );

            let dtpoff = self.relocation_for_symbol(REL_DTPOFF, symbol_name);
            let tls_symbol = unsafe {
                self.helper_dylib()
                    .get::<()>(symbol_name)
                    .unwrap_or_else(|| panic!("missing TLS symbol {symbol_name}"))
                    .into_raw() as usize
            };
            let expected = (tls_symbol - self.helper_dylib().base()) as u64 + dtpoff.addend as u64
                - elf_loader::arch::TLS_DTV_OFFSET as u64;
            assert_eq!(
                self.slot_word(dtpoff),
                expected,
                "REL_DTPOFF mismatch for {symbol_name}"
            );
        }
    }

    pub(crate) fn assert_relative_relocations(&self) {
        let relative = self.anonymous_relocations(REL_RELATIVE)[0];
        assert_eq!(relative.section, SectionKind::Got);
        assert_eq!(
            self.slot_word(relative),
            (self.loaded_dylib().base() as i64 + relative.addend) as u64,
            "REL_RELATIVE mismatch"
        );

        let irelative = self.anonymous_relocations(REL_IRELATIVE)[0];
        assert_eq!(irelative.section, SectionKind::Got);
        assert_eq!(
            self.slot_word(irelative),
            self.loaded_dylib().base() as u64 + IFUNC_RESOLVER_OFFSET,
            "REL_IRELATIVE mismatch"
        );
    }

    #[cfg(feature = "tls")]
    pub(crate) fn assert_tls_values_are_thread_local(&self) {
        let first_tls_helper = self.tls_helper(EXTERNAL_TLS_NAME);
        let second_tls_helper = self.tls_helper(EXTERNAL_TLS_NAME2);

        let thread_count = 4;
        let barrier = Arc::new(Barrier::new(thread_count));
        let handles: Vec<_> = (0..thread_count)
            .map(|index| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let (first_ptr, second_ptr) = (first_tls_helper(), second_tls_helper());
                    unsafe {
                        assert_eq!(*first_ptr, 0xDDCCBBAA);
                        assert_eq!(*second_ptr, 0x44332211);
                        barrier.wait();
                        (*first_ptr, *second_ptr) = (index as u32 + 0x100, index as u32 + 0x200);
                        barrier.wait();
                        assert_eq!(
                            (*first_ptr, *second_ptr),
                            (index as u32 + 0x100, index as u32 + 0x200)
                        );
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("TLS thread panicked");
        }
    }
}
