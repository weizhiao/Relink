#![allow(dead_code)]

use std::collections::HashMap;

#[cfg(feature = "tls")]
use elf_loader::arch::{REL_DTPMOD, REL_DTPOFF};
#[cfg(feature = "lazy-binding")]
use elf_loader::relocation::BindingOptions;
use elf_loader::{
    Loader,
    arch::{REL_COPY, REL_GOT, REL_IRELATIVE, REL_JUMP_SLOT, REL_RELATIVE, REL_SYMBOLIC},
    image::LoadedDylib,
    input::ElfBinary,
};
use gen_elf::{
    Arch, DylibWriter, ElfWriteOutput, ElfWriterConfig, RelocEntry, RelocationInfo, SymbolDesc,
};

use crate::support::{
    dylib_relocation_checks,
    host_symbols::{
        COPY_VAR_NAME, EXTERNAL_FUNC_NAME, EXTERNAL_FUNC_NAME2, EXTERNAL_TLS_NAME,
        EXTERNAL_TLS_NAME2, EXTERNAL_VAR_NAME, F64Pair, LOCAL_VAR_NAME, TestHostSymbols,
    },
};

pub(super) const IFUNC_RESOLVER_OFFSET: u64 = 100;
pub(super) const FLOAT_TOLERANCE: f64 = 0.0001;

type HostExternalFn = extern "C" fn(
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    F64Pair,
    f64,
    f64,
    f64,
    f64,
    f64,
    f64,
    f64,
) -> f64;

#[cfg(feature = "tls")]
type TlsHelperFn = extern "C" fn() -> *mut u32;

fn dynamic_relocation_entries() -> Vec<RelocEntry> {
    let mut relocations = vec![
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, REL_JUMP_SLOT),
        RelocEntry::with_name(EXTERNAL_FUNC_NAME2, REL_JUMP_SLOT),
        RelocEntry::with_name(EXTERNAL_VAR_NAME, REL_GOT),
        RelocEntry::with_name(LOCAL_VAR_NAME, REL_SYMBOLIC),
        RelocEntry::with_name(COPY_VAR_NAME, REL_COPY),
        RelocEntry::new(REL_RELATIVE),
        RelocEntry::new(REL_IRELATIVE),
    ];
    #[cfg(feature = "tls")]
    relocations.extend([
        RelocEntry::with_name(EXTERNAL_TLS_NAME, REL_DTPMOD),
        RelocEntry::with_name(EXTERNAL_TLS_NAME, REL_DTPOFF),
        RelocEntry::with_name(EXTERNAL_TLS_NAME2, REL_DTPMOD),
        RelocEntry::with_name(EXTERNAL_TLS_NAME2, REL_DTPOFF),
    ]);
    relocations
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum BindingMode {
    Eager,
    #[cfg(feature = "lazy-binding")]
    Lazy,
}

impl BindingMode {
    pub(crate) fn is_lazy(self) -> bool {
        match self {
            Self::Eager => false,
            #[cfg(feature = "lazy-binding")]
            Self::Lazy => true,
        }
    }
}

pub(crate) struct BindingFixture {
    main_output: ElfWriteOutput,
    helper_output: ElfWriteOutput,
    host_symbols: TestHostSymbols,
}

impl BindingFixture {
    pub(crate) fn new() -> Self {
        let arch = Arch::current();
        let config = ElfWriterConfig::default().with_ifunc_resolver_val(IFUNC_RESOLVER_OFFSET);

        let mut helper_symbols = vec![SymbolDesc::global_object(
            COPY_VAR_NAME,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        )];
        #[cfg(feature = "tls")]
        helper_symbols.extend([
            SymbolDesc::global_tls(EXTERNAL_TLS_NAME, &[0xAA, 0xBB, 0xCC, 0xDD]),
            SymbolDesc::global_tls(EXTERNAL_TLS_NAME2, &[0x11, 0x22, 0x33, 0x44]),
        ]);

        let helper_output = DylibWriter::with_config(arch, config.clone())
            .write(&[], &helper_symbols)
            .expect("failed to generate helper ELF");

        let mut main_symbols = vec![
            SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 8]),
            SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME),
            SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME2),
            SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
            SymbolDesc::undefined_object(COPY_VAR_NAME).with_size(8),
        ];
        #[cfg(feature = "tls")]
        main_symbols.extend([
            SymbolDesc::undefined_tls(EXTERNAL_TLS_NAME),
            SymbolDesc::undefined_tls(EXTERNAL_TLS_NAME2),
        ]);

        let main_output = DylibWriter::with_config(arch, config)
            .write(&dynamic_relocation_entries(), &main_symbols)
            .expect("failed to generate main ELF");

        Self {
            main_output,
            helper_output,
            host_symbols: TestHostSymbols::new(),
        }
    }

    pub(crate) fn load(self, binding: BindingMode) -> BindingScenario {
        let loader = Loader::new();
        #[cfg(feature = "tls")]
        let mut loader = loader.with_default_tls_resolver();
        #[cfg(not(feature = "tls"))]
        let mut loader = loader;

        let helper_dylib = loader
            .load_dylib(ElfBinary::new("libhelper.so", &self.helper_output.data))
            .expect("failed to load helper")
            .relocator()
            .relocate()
            .expect("failed to relocate helper");

        let pending_dylib = loader
            .load_dylib(ElfBinary::new("test_dynamic.so", &self.main_output.data))
            .expect("failed to load dylib");

        let prepared_relocator = pending_dylib
            .relocator()
            .pre_find(self.host_symbols.resolver.clone())
            .scope(&[helper_dylib.clone()]);

        #[cfg(feature = "lazy-binding")]
        let loaded_dylib = if binding.is_lazy() {
            prepared_relocator
                .binding(BindingOptions::lazy_with_scope(
                    self.host_symbols.resolver.clone(),
                ))
                .relocate()
        } else {
            prepared_relocator.eager().relocate()
        }
        .expect("failed to relocate dylib");

        #[cfg(not(feature = "lazy-binding"))]
        let loaded_dylib = {
            assert!(
                !binding.is_lazy(),
                "lazy binding test requires the `lazy-binding` feature"
            );
            prepared_relocator
                .eager()
                .relocate()
                .expect("failed to relocate dylib")
        };

        BindingScenario {
            binding,
            main_output: self.main_output,
            helper_dylib,
            loaded_dylib,
            host_symbol_addresses: self.host_symbols.addresses,
        }
    }
}

pub(crate) struct BindingScenario {
    binding: BindingMode,
    main_output: ElfWriteOutput,
    helper_dylib: LoadedDylib<()>,
    loaded_dylib: LoadedDylib<()>,
    host_symbol_addresses: HashMap<&'static str, usize>,
}

impl BindingScenario {
    pub(crate) fn binding_mode(&self) -> BindingMode {
        self.binding
    }

    pub(crate) fn loaded_dylib(&self) -> &LoadedDylib<()> {
        &self.loaded_dylib
    }

    pub(crate) fn helper_dylib(&self) -> &LoadedDylib<()> {
        &self.helper_dylib
    }

    pub(crate) fn host_symbol_address(&self, name: &str) -> u64 {
        self.host_symbol_addresses
            .get(name)
            .copied()
            .unwrap_or_else(|| panic!("missing host symbol {name}")) as u64
    }

    pub(crate) fn relocation_for_symbol(&self, r_type: u32, symbol_name: &str) -> &RelocationInfo {
        dylib_relocation_checks::relocation_for_symbol(&self.main_output, r_type, symbol_name)
    }

    pub(crate) fn anonymous_relocations(&self, r_type: u32) -> Vec<&RelocationInfo> {
        dylib_relocation_checks::anonymous_relocations(&self.main_output, r_type)
    }

    pub(crate) fn slot_address(&self, relocation: &RelocationInfo) -> usize {
        dylib_relocation_checks::slot_address(&self.loaded_dylib, relocation)
    }

    pub(crate) fn slot_word(&self, relocation: &RelocationInfo) -> u64 {
        dylib_relocation_checks::slot_word(&self.loaded_dylib, relocation)
    }

    pub(crate) fn loaded_symbol_address(&self, name: &str) -> Option<u64> {
        unsafe {
            self.loaded_dylib
                .get::<*const ()>(name)
                .map(|symbol| symbol.into_raw() as u64)
        }
    }

    pub(crate) fn expected_external_call_result(&self) -> (F64Pair, f64) {
        let vector = F64Pair([9.9, 10.10]);
        let expected = (1..9).sum::<i64>() as f64
            + (1..8).map(|i| i as f64 + i as f64 / 10.0).sum::<f64>()
            + vector.0[0]
            + vector.0[1];
        (vector, expected)
    }

    pub(crate) fn call_plt_helper(&self, symbol_name: &str) -> f64 {
        let helper_name = format!("{symbol_name}@plt_helper");
        let helper_fn: HostExternalFn = unsafe {
            core::mem::transmute(
                self.loaded_dylib
                    .get::<*const ()>(&helper_name)
                    .unwrap_or_else(|| panic!("missing helper symbol {helper_name}"))
                    .into_raw(),
            )
        };

        let (vector, _) = self.expected_external_call_result();
        helper_fn(
            1, 2, 3, 4, 5, 6, 7, 8, vector, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7,
        )
    }

    #[cfg(feature = "tls")]
    pub(crate) fn tls_helper(&self, symbol_name: &str) -> TlsHelperFn {
        let helper_name = format!("{symbol_name}@tls_helper");
        unsafe {
            core::mem::transmute(
                self.loaded_dylib
                    .get::<*const ()>(&helper_name)
                    .unwrap_or_else(|| panic!("missing TLS helper symbol {helper_name}"))
                    .into_raw(),
            )
        }
    }
}
