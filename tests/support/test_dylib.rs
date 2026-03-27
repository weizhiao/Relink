#![allow(dead_code)]

use elf_loader::{Loader, image::LoadedDylib, input::ElfBinary};
use gen_elf::{Arch, DylibWriter, ElfWriteOutput, ElfWriterConfig, RelocEntry, SymbolDesc};

pub(crate) fn write_test_dylib(relocs: &[RelocEntry], symbols: &[SymbolDesc]) -> ElfWriteOutput {
    write_test_dylib_with_config(
        ElfWriterConfig::default().with_bind_now(true),
        relocs,
        symbols,
    )
}

pub(crate) fn write_test_dylib_with_config(
    config: ElfWriterConfig,
    relocs: &[RelocEntry],
    symbols: &[SymbolDesc],
) -> ElfWriteOutput {
    DylibWriter::with_config(Arch::current(), config)
        .write(relocs, symbols)
        .expect("failed to generate test dylib")
}

pub(crate) fn load_relocated_dylib<M>(
    loader: &mut Loader<M>,
    name: &str,
    output: &ElfWriteOutput,
) -> LoadedDylib<()>
where
    M: elf_loader::os::Mmap,
{
    loader
        .load_dylib(ElfBinary::new(name, &output.data))
        .expect("failed to load test dylib")
        .relocator()
        .relocate()
        .expect("failed to relocate test dylib")
}
