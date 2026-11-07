//! Minimal ELF dynamic-object writer.
//!
//! Builds shared objects from caller-provided text and exports, with program
//! headers, `.dynamic`, `.dynsym`, `.dynstr`, and `.hash` metadata.
//! Available in `no_std` builds.

mod builder;
mod hash;
mod layout;
mod string_table;
mod types;
mod writer;

pub use crate::elf::hash::sysv_hash;
pub use builder::DsoBuilder;
pub use types::{DsoExport, DsoExportLayout, DsoImage, DsoSymbolBind, DsoSymbolKind};

#[cfg(test)]
mod tests {
    use super::{DsoBuilder, sysv_hash};
    use crate::{Loader, Relocator, arch::x86_64::X86_64Arch, input::ElfBinary, memory::VmOffset};

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

        let config = Loader::new().with_arch::<X86_64Arch>();
        let mut loader = config.run(crate::runtime::Domain::new(
            crate::runtime::AddressSpaceId::PROCESS,
            crate::runtime::NativeCodeExecutor,
        ));
        let lib = Relocator::new()
            .run(
                loader
                    .load_dylib(ElfBinary::owned("libvirtual.so", image.bytes))
                    .unwrap(),
            )
            .relocate()
            .unwrap();

        let symbol = unsafe { lib.get::<*const ()>("virtual_func").unwrap().unwrap() };
        assert_eq!(
            symbol.into_raw() as usize,
            (lib.segments().base() + VmOffset::new(expected_addr)).get(),
            "symbol value should be relative to the DSO base"
        );
    }
}
