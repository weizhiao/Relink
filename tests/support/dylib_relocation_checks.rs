#![allow(dead_code)]

use elf_loader::{
    image::LoadedCore,
    memory::{RegionAccess, VmOffset},
    relocation::RelocationArch,
    tls::TlsResolver,
};
use gen_elf::{ElfWriteOutput, RelocationInfo};

use crate::support::memory::read_native_word;

pub(crate) fn relocation_for_symbol<'a>(
    output: &'a ElfWriteOutput,
    r_type: u32,
    symbol_name: &str,
) -> &'a RelocationInfo {
    output
        .find_relocation(r_type, symbol_name)
        .unwrap_or_else(|| {
            panic!(
                "missing relocation type {} for symbol {}",
                r_type, symbol_name
            )
        })
}

pub(crate) fn anonymous_relocations(output: &ElfWriteOutput, r_type: u32) -> Vec<&RelocationInfo> {
    let relocations: Vec<_> = output
        .relocations
        .iter()
        .filter(|relocation| relocation.r_type == r_type && relocation.symbol_name.is_none())
        .collect();
    assert!(
        !relocations.is_empty(),
        "missing relocation type {} without symbol",
        r_type
    );
    relocations
}

pub(crate) fn slot_address<D, Arch, R, Tls>(
    image: &LoadedCore<D, Arch, R, Tls>,
    relocation: &RelocationInfo,
) -> usize
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver,
{
    (image.base()
        + VmOffset::new(
            relocation
                .vaddr
                .expect("dynamic relocation metadata should include a virtual address")
                as usize,
        ))
    .get()
}

pub(crate) fn slot_word<D, Arch, R, Tls>(
    image: &LoadedCore<D, Arch, R, Tls>,
    relocation: &RelocationInfo,
) -> u64
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver,
{
    read_native_word(slot_address(image, relocation))
}
