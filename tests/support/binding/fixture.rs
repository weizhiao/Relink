#![allow(dead_code)]

use std::collections::HashMap;

use elf_loader::{
    Loader, arch::NativeArch, image::LoadedCore, input::ElfBinary, relocation::RelocationArch,
};

const REL_COPY: u32 = <NativeArch as RelocationArch>::COPY.raw();
const REL_GOT: u32 = <NativeArch as RelocationArch>::GOT.raw();
const REL_IRELATIVE: u32 = <NativeArch as RelocationArch>::IRELATIVE.raw();
const REL_JUMP_SLOT: u32 = <NativeArch as RelocationArch>::JUMP_SLOT.raw();
const REL_RELATIVE: u32 = <NativeArch as RelocationArch>::RELATIVE.raw();
const REL_SYMBOLIC: u32 = <NativeArch as RelocationArch>::SYMBOLIC.raw();
#[cfg(feature = "tls")]
const REL_DTPMOD: u32 = <NativeArch as RelocationArch>::DTPMOD.raw();
#[cfg(feature = "tls")]
const REL_DTPOFF: u32 = <NativeArch as RelocationArch>::DTPOFF.raw();
use gen_elf::{
    Arch, DylibWriter, ElfWriteOutput, ElfWriterConfig, RelocEntry, RelocationInfo, SymbolDesc,
};

use super::BindingKind;
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
    let relocations = vec![
        RelocEntry::with_name(EXTERNAL_FUNC_NAME, REL_JUMP_SLOT),
        RelocEntry::with_name(EXTERNAL_FUNC_NAME2, REL_JUMP_SLOT),
        RelocEntry::with_name(EXTERNAL_VAR_NAME, REL_GOT),
        RelocEntry::with_name(LOCAL_VAR_NAME, REL_SYMBOLIC),
        RelocEntry::with_name(COPY_VAR_NAME, REL_COPY),
        RelocEntry::new(REL_RELATIVE),
        RelocEntry::new(REL_IRELATIVE),
    ];
    #[cfg(feature = "tls")]
    let relocations = relocations.into_iter().chain([
        RelocEntry::with_name(EXTERNAL_TLS_NAME, REL_DTPMOD),
        RelocEntry::with_name(EXTERNAL_TLS_NAME, REL_DTPOFF),
        RelocEntry::with_name(EXTERNAL_TLS_NAME2, REL_DTPMOD),
        RelocEntry::with_name(EXTERNAL_TLS_NAME2, REL_DTPOFF),
    ]);
    relocations.into_iter().collect()
}

pub(crate) struct BindingFixture {
    helper_output: ElfWriteOutput,
    host_symbols: TestHostSymbols,
}

impl BindingFixture {
    pub(crate) fn new() -> Self {
        let arch = Arch::current();
        let config = ElfWriterConfig::default().with_ifunc_resolver_val(IFUNC_RESOLVER_OFFSET);

        let helper_symbols = vec![SymbolDesc::global_object(
            COPY_VAR_NAME,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        )];
        #[cfg(feature = "tls")]
        let helper_symbols = helper_symbols.into_iter().chain([
            SymbolDesc::global_tls(EXTERNAL_TLS_NAME, &[0xAA, 0xBB, 0xCC, 0xDD]),
            SymbolDesc::global_tls(EXTERNAL_TLS_NAME2, &[0x11, 0x22, 0x33, 0x44]),
        ]);
        let helper_symbols: Vec<_> = helper_symbols.into_iter().collect();

        let helper_output = DylibWriter::with_config(arch, config.clone())
            .write(&[], &helper_symbols)
            .expect("failed to generate helper ELF");

        Self {
            helper_output,
            host_symbols: TestHostSymbols::new(),
        }
    }

    fn write_main_output(&self, binding: BindingKind) -> ElfWriteOutput {
        let arch = Arch::current();
        let config = ElfWriterConfig::default()
            .with_ifunc_resolver_val(IFUNC_RESOLVER_OFFSET)
            .with_bind_now(!binding.is_lazy());

        let main_symbols = vec![
            SymbolDesc::global_object(LOCAL_VAR_NAME, &[0u8; 8]),
            SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME),
            SymbolDesc::undefined_func(EXTERNAL_FUNC_NAME2),
            SymbolDesc::undefined_object(EXTERNAL_VAR_NAME),
            SymbolDesc::undefined_object(COPY_VAR_NAME).with_size(8),
        ];
        #[cfg(feature = "tls")]
        let main_symbols = main_symbols.into_iter().chain([
            SymbolDesc::undefined_tls(EXTERNAL_TLS_NAME),
            SymbolDesc::undefined_tls(EXTERNAL_TLS_NAME2),
        ]);
        let main_symbols: Vec<_> = main_symbols.into_iter().collect();

        DylibWriter::with_config(arch, config)
            .write(&dynamic_relocation_entries(), &main_symbols)
            .expect("failed to generate main ELF")
    }

    pub(crate) fn load(self, binding: BindingKind) -> BindingScenario {
        let main_output = self.write_main_output(binding);
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
            .load_dylib(ElfBinary::new("test_dynamic.so", &main_output.data))
            .expect("failed to load dylib");

        let prepared_relocator = pending_dylib
            .relocator()
            .pre_find(self.host_symbols.resolver.clone())
            .scope(&[helper_dylib.clone()]);

        #[cfg(feature = "lazy-binding")]
        let loaded_dylib = if binding.is_lazy() {
            prepared_relocator.share_find_with_lazy().lazy().relocate()
        } else {
            prepared_relocator.relocate()
        }
        .expect("failed to relocate dylib");

        #[cfg(not(feature = "lazy-binding"))]
        let loaded_dylib = {
            prepared_relocator
                .relocate()
                .expect("failed to relocate dylib")
        };

        BindingScenario {
            binding,
            main_output,
            helper_dylib,
            loaded_dylib,
            host_symbol_addresses: self.host_symbols.addresses,
        }
    }
}

pub(crate) struct BindingScenario {
    binding: BindingKind,
    main_output: ElfWriteOutput,
    helper_dylib: LoadedCore<()>,
    loaded_dylib: LoadedCore<()>,
    host_symbol_addresses: HashMap<&'static str, usize>,
}

impl BindingScenario {
    pub(crate) fn binding_kind(&self) -> BindingKind {
        self.binding
    }

    pub(crate) fn loaded_dylib(&self) -> &LoadedCore<()> {
        &self.loaded_dylib
    }

    pub(crate) fn helper_dylib(&self) -> &LoadedCore<()> {
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
