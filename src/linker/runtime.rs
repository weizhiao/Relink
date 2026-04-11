use super::layout::{
    LayoutArenaId, LayoutMemoryClass, LayoutSectionData, LayoutSectionId, MemoryLayoutPlan,
};
use crate::linker::plan::LinkModuleId;
use crate::{
    AlignedBytes, ByteRepr, Result,
    elf::{
        ElfDyn, ElfDynamicTag, ElfPhdr, ElfPhdrs, ElfProgramType, ElfRelType, ElfSectionType,
        ElfSymbol,
    },
    image::{LoadedMemorySlice, RawDylib, ScannedDylib, ScannedSection, ScannedSectionId},
    loader::DynLifecycleHandler,
    os::{MapFlags, Mmap, ProtFlags},
    segment::{ElfMemoryBacking, ElfSegments},
    tls::{TlsInfo, TlsResolver},
    try_cast_slice, try_cast_slice_mut,
};
use alloc::{boxed::Box, collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};
use core::ptr::NonNull;
use elf::abi::{SHN_ABS, SHN_UNDEF};

type ArenaBaseMap = BTreeMap<LayoutArenaId, usize>;

#[derive(Clone)]
pub(crate) struct MappedArena {
    memory_class: LayoutMemoryClass,
    base: usize,
    len: usize,
    backing: Arc<ElfMemoryBacking>,
}

impl MappedArena {
    #[inline]
    pub(crate) fn base(&self) -> usize {
        self.base
    }

    #[inline]
    fn backing(&self) -> Arc<ElfMemoryBacking> {
        Arc::clone(&self.backing)
    }

    #[inline]
    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.len) }
    }

    #[inline]
    fn slice_mut(&mut self, offset: usize, len: usize) -> Option<&mut [u8]> {
        let end = offset.checked_add(len)?;
        self.bytes_mut().get_mut(offset..end)
    }

    fn protect<M: Mmap>(&self) -> Result<()> {
        if self.len == 0 {
            return Ok(());
        }
        unsafe {
            M::mprotect(
                self.base as *mut _,
                self.len,
                final_protection(self.memory_class),
            )
        }
    }
}

#[derive(Clone, Copy)]
struct RuntimeSection {
    scanned: ScannedSectionId,
    section: LayoutSectionId,
    original_address: usize,
    size: usize,
    actual_address: usize,
    module_offset: usize,
}

impl RuntimeSection {
    fn remap_original_address(self, original_address: usize) -> Option<usize> {
        if self.size == 0 && original_address == self.original_address {
            return Some(self.module_offset);
        }

        let delta = original_address.checked_sub(self.original_address)?;
        (delta < self.size).then_some(self.module_offset + delta)
    }

    fn remap_relocation_offset(self, original_offset: usize) -> Option<usize> {
        if let Some(offset) = self.remap_original_address(original_offset) {
            return Some(offset);
        }

        (original_offset < self.size).then_some(self.module_offset + original_offset)
    }

    fn bytes_mut(self, segments: &ElfSegments) -> Option<&'static mut [u8]> {
        if self.size == 0 {
            return None;
        }

        Some(segments.get_slice_mut::<u8>(self.module_offset, self.size))
    }

    fn memory_slice(self) -> LoadedMemorySlice {
        LoadedMemorySlice::new(self.actual_address, self.size)
    }
}

#[derive(Clone, Copy)]
struct SymbolValue {
    value: usize,
    section_index: usize,
}

struct RuntimeModuleMemory {
    base: usize,
    segments: ElfSegments,
    memory_slices: Box<[LoadedMemorySlice]>,
    sections: Box<[RuntimeSection]>,
}

impl RuntimeModuleMemory {
    fn section_by_layout(&self, section: LayoutSectionId) -> Option<RuntimeSection> {
        self.sections
            .iter()
            .find(|candidate| candidate.section == section)
            .copied()
    }

    fn section_by_scanned(&self, scanned: ScannedSectionId) -> Option<RuntimeSection> {
        self.sections
            .iter()
            .find(|candidate| candidate.scanned == scanned)
            .copied()
    }

    fn remap_original_address(
        &self,
        original_address: usize,
        preferred: Option<ScannedSectionId>,
    ) -> Option<usize> {
        preferred
            .into_iter()
            .chain(self.sections.iter().map(|section| section.scanned))
            .find_map(|scanned| {
                self.section_by_scanned(scanned)?
                    .remap_original_address(original_address)
            })
    }

    fn remap_symbol_value(&self, symbol: SymbolValue) -> Option<usize> {
        if symbol.section_index == SHN_UNDEF as usize || symbol.section_index == SHN_ABS as usize {
            return Some(symbol.value);
        }

        let section = self.section_by_scanned(symbol.section_index)?;
        section.remap_original_address(symbol.value).or_else(|| {
            (symbol.value < section.size).then_some(section.module_offset + symbol.value)
        })
    }

    fn remap_runtime_relocation_offset(
        &self,
        target: Option<LayoutSectionId>,
        original_offset: usize,
    ) -> Option<usize> {
        target
            .and_then(|section_id| self.section_by_layout(section_id))
            .and_then(|section| section.remap_relocation_offset(original_offset))
            .or_else(|| self.remap_original_address(original_offset, None))
    }

    fn actual_address_for_layout(
        &self,
        arena_bases: &ArenaBaseMap,
        address: super::layout::LayoutAddress,
    ) -> Option<usize> {
        arena_bases
            .get(&address.arena())
            .and_then(|base| base.checked_add(address.offset()))
    }
}

struct RuntimeMetadataRewriter<'a, D: 'static> {
    module_id: LinkModuleId,
    scanned: &'a ScannedDylib<D>,
    layout: &'a MemoryLayoutPlan,
    runtime: &'a RuntimeModuleMemory,
}

impl<'a, D> RuntimeMetadataRewriter<'a, D>
where
    D: 'static,
{
    fn new(
        module_id: LinkModuleId,
        scanned: &'a ScannedDylib<D>,
        layout: &'a MemoryLayoutPlan,
        runtime: &'a RuntimeModuleMemory,
    ) -> Self {
        Self {
            module_id,
            scanned,
            layout,
            runtime,
        }
    }

    fn rewrite(&self) -> Result<()> {
        self.rewrite_symbol_tables()?;
        self.rewrite_allocated_relocation_sections()?;
        self.rewrite_dynamic_section()?;
        Ok(())
    }

    fn rewrite_symbol_tables(&self) -> Result<()> {
        self.rewrite_sections(
            |section| {
                matches!(
                    section.section_type(),
                    ElfSectionType::SYMTAB | ElfSectionType::DYNSYM
                )
            },
            |_, bytes| {
                let symbols = typed_slice_mut::<ElfSymbol>(bytes)?;
                for elf_symbol in symbols {
                    let symbol = SymbolValue {
                        value: elf_symbol.st_value(),
                        section_index: elf_symbol.st_shndx(),
                    };
                    if let Some(value) = self.runtime.remap_symbol_value(symbol) {
                        elf_symbol.set_value(value);
                    }
                }
                Ok(())
            },
        )
    }

    fn rewrite_allocated_relocation_sections(&self) -> Result<()> {
        self.rewrite_sections(
            |section| section.is_allocated() && section.is_relocation_section(),
            |section, bytes| {
                let Some(layout_section) =
                    self.layout.module_section_id(self.module_id, section.id())
                else {
                    return Err(crate::custom_error(
                        "retained relocation section is missing from the layout",
                    ));
                };
                let Some(relocation) = self.layout.section_metadata(layout_section).info_section()
                else {
                    return Err(crate::custom_error(
                        "retained relocation section is missing relocation metadata",
                    ));
                };
                let rels = typed_slice_mut::<ElfRelType>(bytes)?;
                for rel in rels {
                    if let Some(offset) = self
                        .runtime
                        .remap_runtime_relocation_offset(Some(relocation), rel.r_offset())
                    {
                        rel.set_offset(offset);
                    }
                }
                Ok(())
            },
        )
    }

    fn rewrite_dynamic_section(&self) -> Result<()> {
        let phdr = program_header(self.scanned.phdrs(), ElfProgramType::DYNAMIC)
            .ok_or_else(|| crate::custom_error("arena-backed module is missing PT_DYNAMIC"))?;
        let offset = self
            .runtime
            .remap_original_address(phdr.p_vaddr(), None)
            .ok_or_else(|| {
                crate::custom_error("failed to remap PT_DYNAMIC into arena-backed memory")
            })?;
        let dyns = self
            .runtime
            .segments
            .get_slice_mut::<ElfDyn>(offset, phdr.p_memsz());
        for dyn_ in dyns {
            if let Some(rewritten) = remap_dynamic_value(self.runtime, dyn_.tag(), dyn_.value()) {
                dyn_.set_value(rewritten);
            }
            if dyn_.tag() == ElfDynamicTag::NULL {
                break;
            }
        }
        Ok(())
    }

    fn rewrite_sections<P, F>(&self, mut predicate: P, mut rewrite: F) -> Result<()>
    where
        P: FnMut(ScannedSection<'_>) -> bool,
        F: FnMut(ScannedSection<'_>, &mut [u8]) -> Result<()>,
    {
        for section in self.scanned.sections() {
            if !predicate(section) {
                continue;
            }
            let Some(bytes) = self.section_bytes_mut(section.id()) else {
                continue;
            };
            rewrite(section, bytes)?;
        }
        Ok(())
    }

    fn section_bytes_mut(&self, scanned_section: ScannedSectionId) -> Option<&'static mut [u8]> {
        let layout_section = self
            .layout
            .module_section_id(self.module_id, scanned_section)?;
        self.runtime
            .section_by_layout(layout_section)?
            .bytes_mut(&self.runtime.segments)
    }
}

pub(crate) fn map_layout_arenas<M>(
    layout: &MemoryLayoutPlan,
    load_section_data: impl FnMut(LayoutSectionId) -> Result<Option<AlignedBytes>>,
) -> Result<BTreeMap<LayoutArenaId, MappedArena>>
where
    M: Mmap,
{
    let mut arenas = allocate_mapped_arenas::<M>(layout)?;
    populate_mapped_arenas(layout, &mut arenas, load_section_data)?;
    Ok(arenas)
}

fn allocate_mapped_arenas<M>(
    layout: &MemoryLayoutPlan,
) -> Result<BTreeMap<LayoutArenaId, MappedArena>>
where
    M: Mmap,
{
    let mut arenas = BTreeMap::new();

    for (id, arena) in layout.arena_entries() {
        let len = layout
            .arena_usage(id)
            .map(|usage| usage.mapped_len())
            .unwrap_or(0);
        if len == 0 {
            continue;
        }

        let ptr = unsafe {
            M::mmap_anonymous(
                0,
                len,
                initial_protection(arena.memory_class()),
                MapFlags::MAP_PRIVATE,
            )
        }?;

        let backing = ElfSegments::create_backing(ptr, len, M::munmap);
        arenas.insert(
            id,
            MappedArena {
                memory_class: arena.memory_class(),
                base: ptr as usize,
                len,
                backing,
            },
        );
    }

    Ok(arenas)
}

fn populate_mapped_arenas(
    layout: &MemoryLayoutPlan,
    arenas: &mut BTreeMap<LayoutArenaId, MappedArena>,
    mut load_section_data: impl FnMut(LayoutSectionId) -> Result<Option<AlignedBytes>>,
) -> Result<()> {
    for (section_id, record) in layout.sections().iter_records() {
        let Some(placement) = record.placement() else {
            continue;
        };
        let metadata = record.metadata();
        if !metadata.is_allocated() {
            continue;
        }

        let arena = arenas.get_mut(&placement.arena()).ok_or_else(|| {
            crate::custom_error("mapped section arenas referenced a missing arena")
        })?;
        let dst = arena
            .slice_mut(placement.offset(), placement.size())
            .ok_or_else(|| {
                crate::custom_error(
                    "mapped section arena placement exceeds the allocated arena bounds",
                )
            })?;

        if let Some(data) = record.data() {
            copy_section_data(data, dst)?;
            continue;
        }

        if metadata.zero_fill() {
            continue;
        }

        let Some(bytes) = load_section_data(section_id)? else {
            return Err(crate::custom_error(
                "mapped section arenas are missing materialized section data",
            ));
        };
        copy_section_bytes(bytes.as_ref(), dst)?;
    }

    Ok(())
}

fn copy_section_data(data: &LayoutSectionData, dst: &mut [u8]) -> Result<()> {
    match data {
        LayoutSectionData::Bytes(bytes) => copy_section_bytes(bytes.as_ref(), dst),
        LayoutSectionData::ZeroFill { size } => {
            if *size != dst.len() {
                return Err(crate::custom_error(
                    "mapped section arena zero-fill size does not match its placement",
                ));
            }
            Ok(())
        }
    }
}

fn copy_section_bytes(bytes: &[u8], dst: &mut [u8]) -> Result<()> {
    if bytes.len() != dst.len() {
        return Err(crate::custom_error(
            "mapped section arena size does not match its materialized section bytes",
        ));
    }

    dst.copy_from_slice(bytes);
    Ok(())
}

pub(crate) fn protect_mapped_arenas<M>(arenas: &BTreeMap<LayoutArenaId, MappedArena>) -> Result<()>
where
    M: Mmap,
{
    for arena in arenas.values() {
        arena.protect::<M>()?;
    }
    Ok(())
}

pub(crate) fn build_arena_raw_dylib<D, Tls>(
    module_id: LinkModuleId,
    mut scanned: ScannedDylib<D>,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &BTreeMap<LayoutArenaId, MappedArena>,
    init_fn: DynLifecycleHandler,
    fini_fn: DynLifecycleHandler,
    force_static_tls: bool,
) -> Result<RawDylib<D>>
where
    D: Default + 'static,
    Tls: TlsResolver,
{
    let runtime = build_runtime_memory(module_id, layout, mapped_section_arenas)?;
    apply_retained_relocations(
        module_id,
        &mut scanned,
        layout,
        &runtime,
        mapped_section_arenas,
    )?;
    RuntimeMetadataRewriter::new(module_id, &scanned, layout, &runtime).rewrite()?;

    let original_phdrs = scanned.phdrs().to_vec();
    let dynamic_ptr = dynamic_ptr(&original_phdrs, &runtime)?;
    let eh_frame_hdr = eh_frame_hdr(&original_phdrs, &runtime);
    let tls_info = tls_info(&original_phdrs, &runtime);
    let entry = remap_entry(scanned.ehdr().e_entry(), &runtime);
    let name = scanned.name().to_string();
    let user_data = core::mem::take(scanned.user_data_mut());

    RawDylib::from_parts::<Tls>(crate::image::DynamicImageParts {
        name,
        entry,
        interp: None,
        phdrs: ElfPhdrs::Vec(original_phdrs),
        dynamic_ptr,
        eh_frame_hdr,
        tls_info,
        force_static_tls,
        relro: None,
        segments: runtime.segments,
        memory_slices: runtime.memory_slices,
        init_fn,
        fini_fn,
        user_data,
    })
}

fn build_runtime_memory(
    module_id: LinkModuleId,
    layout: &MemoryLayoutPlan,
    mapped_section_arenas: &BTreeMap<LayoutArenaId, MappedArena>,
) -> Result<RuntimeModuleMemory> {
    let _module = layout
        .module(module_id)
        .ok_or_else(|| crate::custom_error("arena-backed module is missing from the layout"))?;
    let physical = layout.module_physical_layout(module_id).ok_or_else(|| {
        crate::custom_error("arena-backed module is missing its physical slice layout")
    })?;

    let mut sections = Vec::new();
    for slice in physical.slices() {
        let metadata = layout.section_metadata(slice.section());
        let scanned_id = metadata.scanned_section();
        let arena = mapped_section_arenas.get(&slice.arena()).ok_or_else(|| {
            crate::custom_error("arena-backed module referenced an unmapped arena")
        })?;
        sections.push(RuntimeSection {
            scanned: scanned_id,
            section: slice.section(),
            original_address: metadata.original_address(),
            size: metadata.size(),
            actual_address: arena.base() + slice.offset(),
            module_offset: 0,
        });
    }

    if sections.is_empty() {
        return Err(crate::custom_error(
            "arena-backed module does not own any alloc sections",
        ));
    }

    let base = sections
        .iter()
        .map(|section| section.actual_address)
        .min()
        .ok_or_else(|| crate::custom_error("arena-backed module has no mapped section base"))?;

    for section in &mut sections {
        section.module_offset = section.actual_address - base;
    }

    let mut segment_slices = Vec::with_capacity(sections.len());
    let mut memory_slices = sections
        .iter()
        .map(|section| section.memory_slice())
        .collect::<Vec<_>>();
    memory_slices.sort_by_key(|slice| slice.base());

    for section in &sections {
        let arena_id = layout
            .section_placement(section.section)
            .map(|placement| placement.arena())
            .ok_or_else(|| crate::custom_error("arena-backed module lost a section placement"))?;
        let arena = mapped_section_arenas.get(&arena_id).ok_or_else(|| {
            crate::custom_error("arena-backed module referenced an unmapped arena")
        })?;
        segment_slices.push(ElfSegments::slice(
            section.module_offset,
            section.size,
            arena.backing(),
        ));
    }

    Ok(RuntimeModuleMemory {
        base,
        segments: ElfSegments::from_slices(base, segment_slices),
        memory_slices: memory_slices.into_boxed_slice(),
        sections: sections.into_boxed_slice(),
    })
}

fn apply_retained_relocations<D>(
    module_id: LinkModuleId,
    scanned: &mut ScannedDylib<D>,
    layout: &MemoryLayoutPlan,
    runtime: &RuntimeModuleMemory,
    mapped_section_arenas: &BTreeMap<LayoutArenaId, MappedArena>,
) -> Result<()>
where
    D: 'static,
{
    let derived = layout.module_derived(module_id).ok_or_else(|| {
        crate::custom_error("arena-backed module is missing derived relocation state")
    })?;
    let arena_bases = mapped_section_arenas
        .iter()
        .map(|(id, arena)| (*id, arena.base()))
        .collect::<ArenaBaseMap>();

    for (_, relocation) in derived.relocation_repairs() {
        let symbols = load_symbol_table(relocation.symbol_table_section(), layout, scanned)?;

        for site in relocation.sites() {
            let Some(actual_site) = runtime.actual_address_for_layout(&arena_bases, site.address())
            else {
                continue;
            };
            let Some(symbol) = symbols.get(site.symbol_index()).copied() else {
                continue;
            };
            let symbol_value = runtime.remap_symbol_value(symbol).unwrap_or(symbol.value);
            let value = rewrite_relocation_value(
                site.relocation_type(),
                symbol_value,
                site.addend(),
                actual_site - runtime.base,
            )?;
            write_relocation_value(actual_site, site.relocation_type(), value)?;
        }
    }

    Ok(())
}

fn dynamic_ptr(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Result<NonNull<ElfDyn>> {
    let phdr = program_header(phdrs, ElfProgramType::DYNAMIC)
        .ok_or_else(|| crate::custom_error("arena-backed module is missing PT_DYNAMIC"))?;
    let offset = runtime
        .remap_original_address(phdr.p_vaddr(), None)
        .ok_or_else(|| crate::custom_error("failed to remap PT_DYNAMIC"))?;
    NonNull::new(runtime.segments.get_mut_ptr(offset))
        .ok_or_else(|| crate::custom_error("PT_DYNAMIC remapped to a null pointer"))
}

fn eh_frame_hdr(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Option<NonNull<u8>> {
    let phdr = program_header(phdrs, ElfProgramType::GNU_EH_FRAME)?;
    let offset = runtime.remap_original_address(phdr.p_vaddr(), None)?;
    NonNull::new(runtime.segments.get_mut_ptr(offset))
}

fn tls_info(phdrs: &[ElfPhdr], runtime: &RuntimeModuleMemory) -> Option<TlsInfo> {
    let phdr = program_header(phdrs, ElfProgramType::TLS)?;
    let offset = runtime.remap_original_address(phdr.p_vaddr(), None)?;
    let image = runtime.segments.get_slice::<u8>(offset, phdr.p_filesz());
    Some(TlsInfo::new(phdr, image))
}

fn remap_entry(
    original_entry: usize,
    runtime: &RuntimeModuleMemory,
) -> crate::relocation::RelocAddr {
    runtime
        .remap_original_address(original_entry, None)
        .map(|offset| runtime.segments.base_addr().offset(offset))
        .unwrap_or_else(|| runtime.segments.base_addr().offset(original_entry))
}

fn load_symbol_table<D>(
    section: Option<LayoutSectionId>,
    layout: &MemoryLayoutPlan,
    scanned: &mut ScannedDylib<D>,
) -> Result<Box<[SymbolValue]>>
where
    D: 'static,
{
    let Some(section) = section else {
        return Ok(Vec::new().into_boxed_slice());
    };
    let bytes = owned_section_bytes(section, layout, scanned)?
        .ok_or_else(|| crate::custom_error("retained relocation symbol table is missing"))?;
    let symbols = typed_slice::<ElfSymbol>(bytes.as_ref())?;
    Ok(symbols
        .iter()
        .map(|symbol| SymbolValue {
            value: symbol.st_value(),
            section_index: symbol.st_shndx(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice())
}

fn owned_section_bytes<D>(
    section: LayoutSectionId,
    layout: &MemoryLayoutPlan,
    scanned: &mut ScannedDylib<D>,
) -> Result<Option<AlignedBytes>>
where
    D: 'static,
{
    if let Some(data) = layout.cached_section_data(section) {
        return Ok(Some(match data {
            LayoutSectionData::Bytes(bytes) => bytes.clone(),
            LayoutSectionData::ZeroFill { size } => {
                AlignedBytes::with_len(*size).expect("failed to allocate section bytes")
            }
        }));
    }

    let scanned_section = layout.section_metadata(section).scanned_section();

    scanned.section_data(scanned_section)
}

fn typed_slice<T: ByteRepr>(bytes: &[u8]) -> Result<&[T]> {
    try_cast_slice(bytes)
        .ok_or_else(|| crate::custom_error("section bytes do not match the requested type layout"))
}

fn typed_slice_mut<T: ByteRepr>(bytes: &mut [u8]) -> Result<&mut [T]> {
    try_cast_slice_mut(bytes)
        .ok_or_else(|| crate::custom_error("section bytes do not match the requested type layout"))
}

fn program_header(phdrs: &[ElfPhdr], kind: ElfProgramType) -> Option<&ElfPhdr> {
    phdrs.iter().find(|phdr| phdr.program_type() == kind)
}

fn remap_dynamic_value(
    runtime: &RuntimeModuleMemory,
    tag: ElfDynamicTag,
    value: usize,
) -> Option<usize> {
    match tag {
        ElfDynamicTag::PLTGOT
        | ElfDynamicTag::HASH
        | ElfDynamicTag::GNU_HASH
        | ElfDynamicTag::STRTAB
        | ElfDynamicTag::SYMTAB
        | ElfDynamicTag::JMPREL
        | ElfDynamicTag::RELR
        | ElfDynamicTag::RELA
        | ElfDynamicTag::REL
        | ElfDynamicTag::INIT
        | ElfDynamicTag::FINI
        | ElfDynamicTag::INIT_ARRAY
        | ElfDynamicTag::FINI_ARRAY
        | ElfDynamicTag::VERSYM
        | ElfDynamicTag::VERNEED
        | ElfDynamicTag::VERDEF => runtime.remap_original_address(value, None),
        _ => None,
    }
}

fn rewrite_relocation_value(
    relocation_type: usize,
    symbol_value: usize,
    addend: crate::image::ScannedRelocationAddend,
    new_place: usize,
) -> Result<RewrittenRelocationValue> {
    #[cfg(target_arch = "x86_64")]
    {
        let addend = match addend {
            crate::image::ScannedRelocationAddend::Explicit(addend) => addend,
            crate::image::ScannedRelocationAddend::Implicit => {
                return Err(crate::custom_error(
                    "implicit retained relocation addends are not supported on x86_64",
                ));
            }
        };
        let symbol_value = symbol_value as i128;
        let addend = addend as i128;
        let new_place = new_place as i128;

        let value = match relocation_type as u32 {
            elf::abi::R_X86_64_NONE => return Ok(RewrittenRelocationValue::Skip),
            elf::abi::R_X86_64_64 => {
                RewrittenRelocationValue::U64((symbol_value + addend) as usize)
            }
            elf::abi::R_X86_64_32 => RewrittenRelocationValue::U32(
                u32::try_from(symbol_value + addend).map_err(|_| {
                    crate::custom_error(
                        "retained relocation overflowed while rewriting R_X86_64_32",
                    )
                })?,
            ),
            elf::abi::R_X86_64_32S => RewrittenRelocationValue::I32(
                i32::try_from(symbol_value + addend).map_err(|_| {
                    crate::custom_error(
                        "retained relocation overflowed while rewriting R_X86_64_32S",
                    )
                })?,
            ),
            elf::abi::R_X86_64_PC32 | elf::abi::R_X86_64_PLT32 | elf::abi::R_X86_64_GOTPCREL => {
                let new = symbol_value + addend - new_place;
                RewrittenRelocationValue::I32(i32::try_from(new).map_err(|_| {
                    crate::custom_error(
                        "retained relocation overflowed while rewriting x86_64 PC-relative relocation",
                    )
                })?)
            }
            _ => {
                return Err(crate::custom_error(
                    "unsupported retained relocation type for x86_64 arena repair",
                ));
            }
        };

        Ok(value)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (relocation_type, symbol_value, addend, new_place);
        Err(crate::custom_error(
            "arena-backed retained relocation repair is not implemented for this architecture",
        ))
    }
}

fn initial_protection(class: LayoutMemoryClass) -> ProtFlags {
    match class {
        LayoutMemoryClass::Code => {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC
        }
        LayoutMemoryClass::ReadOnlyData
        | LayoutMemoryClass::WritableData
        | LayoutMemoryClass::ThreadLocalData => ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
    }
}

fn final_protection(class: LayoutMemoryClass) -> ProtFlags {
    match class {
        LayoutMemoryClass::Code => ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        LayoutMemoryClass::ReadOnlyData => ProtFlags::PROT_READ,
        LayoutMemoryClass::WritableData | LayoutMemoryClass::ThreadLocalData => {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        }
    }
}

enum RewrittenRelocationValue {
    Skip,
    U64(usize),
    U32(u32),
    I32(i32),
}

fn write_relocation_value(
    actual_site: usize,
    _relocation_type: usize,
    value: RewrittenRelocationValue,
) -> Result<()> {
    match value {
        RewrittenRelocationValue::Skip => {}
        RewrittenRelocationValue::U64(value) => unsafe {
            (actual_site as *mut usize).write(value);
        },
        RewrittenRelocationValue::U32(value) => unsafe {
            (actual_site as *mut u32).write(value);
        },
        RewrittenRelocationValue::I32(value) => unsafe {
            (actual_site as *mut i32).write(value);
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::layout::{
        LayoutArena, LayoutArenaSharing, LayoutSectionKind, LayoutSectionMetadata,
    };
    use super::*;
    use crate::linker::plan::LinkModuleId;
    use crate::os::DefaultMmap;

    #[test]
    fn map_layout_arenas_loads_missing_section_data_on_demand() {
        let mut layout = MemoryLayoutPlan::new();
        let section = layout.sections_mut().insert(
            LinkModuleId::new(0),
            LayoutSectionMetadata::new(
                1,
                ".rodata",
                LayoutSectionKind::Allocated(LayoutMemoryClass::ReadOnlyData),
                None::<LayoutSectionId>,
                None::<LayoutSectionId>,
                0,
                0,
                4,
                4,
                false,
            ),
        );
        let arena = layout.create_arena(LayoutArena::new(
            4096,
            LayoutMemoryClass::ReadOnlyData,
            LayoutArenaSharing::Shared,
        ));
        assert!(layout.assign_section_to_arena(section, arena, 0));

        let mut calls = 0usize;
        let mut mapped = map_layout_arenas::<DefaultMmap>(&layout, |requested| {
            assert_eq!(requested, section);
            calls += 1;
            Ok(Some([1_u8, 2, 3, 4].into()))
        })
        .unwrap();

        assert_eq!(calls, 1);
        let mapped_arena = mapped.get_mut(&arena).unwrap();
        assert_eq!(&mapped_arena.bytes_mut()[0..4], [1_u8, 2, 3, 4].as_slice());
    }
}
