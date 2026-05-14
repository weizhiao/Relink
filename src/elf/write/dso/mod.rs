//! Minimal ELF dynamic-object writer.
//!
//! This module contains the small, no-std writer used to manufacture ELF
//! shared objects that are meant to enter the regular dynamic-linking path.
//! It intentionally focuses on ABI-visible metadata: program headers,
//! `.dynamic`, `.dynsym`, `.dynstr`, `.hash`, and caller-provided text bytes.

mod builder;
mod hash;
mod layout;
mod string_table;
mod types;
mod writer;

pub use builder::DsoBuilder;
pub use hash::sysv_hash;
pub use types::{DsoExport, DsoExportLayout, DsoImage, DsoSymbolBind, DsoSymbolKind};

#[cfg(test)]
mod tests {
    use super::{DsoBuilder, sysv_hash};
    use crate::{
        Loader, arch::x86_64::relocation::X86_64Arch, input::ElfBinary, relocation::RelocationArch,
    };

    #[test]
    fn sysv_hash_matches_known_value() {
        assert_eq!(sysv_hash(b"printf"), 0x077905a6);
    }

    #[test]
    fn generated_dso_loads_and_exports_symbol() {
        let mut builder = DsoBuilder::<X86_64Arch>::new("libvirtual.so");
        builder.add_function("virtual_func", &[0xcc]);
        let image = builder.build().unwrap();
        let expected_addr = image.exports[0].value;

        let mut loader = Loader::new().for_arch::<X86_64Arch>();
        let lib = loader
            .load_dylib(ElfBinary::owned("libvirtual.so", image.bytes))
            .unwrap()
            .relocator()
            .relocate()
            .unwrap();

        let symbol = unsafe { lib.get::<*const ()>("virtual_func").unwrap() };
        assert_eq!(
            symbol.into_raw() as usize,
            lib.base() + expected_addr,
            "symbol value should be relative to the DSO base"
        );
        assert_eq!(X86_64Arch::MACHINE.raw(), 62);
    }
}
