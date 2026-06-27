use super::{RuntimeModuleMemory, RuntimeOffset, RuntimeSectionMemory, SectionId};
use crate::linker::scan::{LinkPlan, ModuleId};
use crate::{
    LinkerError, RelocReason, Result,
    aligned_bytes::ByteRepr,
    elf::{
        ElfDyn, ElfDynamicTag, ElfLayout, ElfRelEntry, ElfRelType, ElfRelocationType, ElfSectionId,
        ElfSymbol,
    },
    memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
    relocation::{RelocationArch, RelocationValueInput, RelocationValueProvider},
    tls::TlsResolver,
    try_cast_bytes,
};
use alloc::{vec, vec::Vec};
use core::{cell::Cell, mem::size_of};

#[derive(Clone, Copy)]
struct RelocationSite {
    place: RuntimeOffset,
    section_offset: usize,
}

#[derive(Clone, Copy)]
struct RelocationSection<'a> {
    memory: &'a RuntimeSectionMemory,
    offset: usize,
}

#[derive(Clone, Copy)]
struct RelocationEntryInfo {
    r_type: ElfRelocationType,
    offset: VmOffset,
}

/// Architecture-specific recovery of GOT/PLT-style retained relocation targets.
pub(crate) trait GotPltTarget {
    fn got_plt_target(
        _target_bytes: &[u8],
        _relocation_type: ElfRelocationType,
        _symbol_is_undef: bool,
        _section_offset: usize,
        _source_place: usize,
        _addend: isize,
    ) -> Result<Option<usize>> {
        Ok(None)
    }
}

impl RelocationEntryInfo {
    fn new<Arch>(entry: &ElfRelType<Arch>) -> Self
    where
        Arch: RelocationArch,
    {
        Self {
            r_type: entry.r_type(),
            offset: entry.r_offset(),
        }
    }
}

impl<R: RegionAccess> RuntimeModuleMemory<R> {
    fn section(&self, section: SectionId) -> Option<&RuntimeSectionMemory> {
        self.sections
            .iter()
            .find(|runtime_section| runtime_section.section == section)
    }

    fn remap_symbol_value(&self, section: Option<SectionId>, value: usize) -> Result<usize> {
        let Some(section_id) = section else {
            return Ok(value);
        };
        let Some(section) = self.section(section_id) else {
            return Err(LinkerError::metadata_rewrite(
                "arena-backed symbol value referenced an unplaced section",
            )
            .into());
        };
        if let Some(offset) = section.runtime_offset(VmOffset::new(value)) {
            return Ok(offset.get());
        }
        Err(LinkerError::metadata_rewrite(
            "arena-backed symbol value does not map into its target section",
        )
        .into())
    }

    fn section_addr(&self, section_id: SectionId) -> Result<VmAddr> {
        let section = self
            .section(section_id)
            .ok_or_else(|| LinkerError::metadata_rewrite("runtime section is not arena-backed"))?;
        Ok(self.base() + VmOffset::new(section.runtime_offset.get()))
    }

    fn read_section_bytes(&self, section_id: SectionId) -> Result<Vec<u8>> {
        let section = self
            .section(section_id)
            .ok_or_else(|| LinkerError::metadata_rewrite("runtime section is not arena-backed"))?;
        let mut bytes = vec![0; section.size];
        self.read_bytes(self.section_addr(section_id)?, &mut bytes)?;
        Ok(bytes)
    }

    fn section_entry_count<T: ByteRepr>(&self, section_id: SectionId) -> Result<usize> {
        let section = self
            .section(section_id)
            .ok_or_else(|| LinkerError::metadata_rewrite("runtime section is not arena-backed"))?;
        let entry_size = size_of::<T>();
        if entry_size == 0 || section.size % entry_size != 0 {
            return Err(LinkerError::metadata_rewrite(
                "runtime section bytes do not match the requested entry type layout",
            )
            .into());
        }
        Ok(section.size / entry_size)
    }

    fn section_entry_addr<T: ByteRepr>(
        &self,
        section_id: SectionId,
        index: usize,
    ) -> Result<VmAddr> {
        let section_addr = self.section_addr(section_id)?;
        let offset = index.checked_mul(size_of::<T>()).ok_or_else(|| {
            LinkerError::metadata_rewrite("runtime section entry offset overflowed")
        })?;
        Ok(section_addr + VmOffset::new(offset))
    }

    fn read_section_entry<T: ByteRepr>(&self, section_id: SectionId, index: usize) -> Result<T> {
        let addr = self.section_entry_addr::<T>(section_id, index)?;
        unsafe { self.read_value::<T>(addr) }
    }

    fn write_section_entry<T: ByteRepr>(
        &self,
        section_id: SectionId,
        index: usize,
        value: T,
    ) -> Result<()> {
        let addr = self.section_entry_addr::<T>(section_id, index)?;
        unsafe { self.write_value(addr, value) }
    }

    fn relocation_site(&self, section: RelocationSection<'_>) -> Result<RelocationSite> {
        let place = section
            .memory
            .runtime_offset
            .checked_add(section.offset)
            .ok_or_else(|| {
                LinkerError::metadata_rewrite("arena-backed runtime offset overflowed")
            })?;
        Ok(RelocationSite {
            place,
            section_offset: section.offset,
        })
    }

    fn relocation_section(
        &self,
        target: Option<SectionId>,
        source_address: VmOffset,
    ) -> Result<RelocationSection<'_>> {
        if let Some(section_id) = target {
            return self.relocation_in_section(section_id, source_address);
        }

        if let Some(section_id) = self.addr_to_section(source_address) {
            return self.relocation_in_section(section_id, source_address);
        }

        Err(LinkerError::metadata_rewrite(
            "allocated relocation entry offset does not map into arena-backed memory",
        )
        .into())
    }

    fn relocation_in_section(
        &self,
        section_id: SectionId,
        source_address: VmOffset,
    ) -> Result<RelocationSection<'_>> {
        let section = self.section(section_id).ok_or_else(|| {
            LinkerError::metadata_rewrite("relocation target section is not arena-backed")
        })?;
        let offset = section.source_offset(source_address).ok_or_else(|| {
            LinkerError::metadata_rewrite("relocation offset does not map into its target section")
        })?;
        Ok(RelocationSection {
            memory: section,
            offset,
        })
    }

    fn addr_to_section(&self, source_address: VmOffset) -> Option<SectionId> {
        self.sections.iter().find_map(|section| {
            section
                .source_offset(source_address)
                .map(|_| section.section)
        })
    }

    fn remap_relocation_addend(&self, addend: isize) -> Result<(RuntimeOffset, isize)> {
        let source_address = usize::try_from(addend).map(VmOffset::new).map_err(|_| {
            LinkerError::metadata_rewrite("allocated relocation addend should be a source address")
        })?;
        let runtime_offset = self
            .remap_source_to_runtime_offset(source_address)
            .ok_or_else(|| {
                LinkerError::metadata_rewrite(
                    "allocated relocation addend should map into arena-backed memory",
                )
            })?;
        let runtime_addend = isize::try_from(runtime_offset.get()).map_err(|_| {
            LinkerError::metadata_rewrite("runtime relocation addend should fit in isize")
        })?;

        Ok((runtime_offset, runtime_addend))
    }

    fn remap_dynamic_value(
        &self,
        tag: ElfDynamicTag,
        value: usize,
    ) -> Result<Option<RuntimeOffset>> {
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
            | ElfDynamicTag::VERDEF => self
                .remap_source_to_runtime_offset(VmOffset::new(value))
                .map(Some)
                .ok_or_else(|| {
                    LinkerError::metadata_rewrite(
                        "dynamic tag does not map into arena-backed memory",
                    )
                })
                .map_err(Into::into),
            _ => Ok(None),
        }
    }
}

pub(crate) struct RuntimeMetadataRewriter<
    'a,
    K,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    module_id: ModuleId,
    plan: &'a mut LinkPlan<K, Arch, Tls>,
    runtime: &'a RuntimeModuleMemory<R>,
}

struct RewriteContext<'a, K, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> = ()> {
    plan: &'a LinkPlan<K, Arch, Tls>,
    module_id: ModuleId,
    runtime: &'a RuntimeModuleMemory<R>,
}

impl<'a, K, Arch, R, Tls> RuntimeMetadataRewriter<'a, K, Arch, R, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    ElfRelType<Arch>: ByteRepr,
{
    pub(crate) fn new(
        module_id: ModuleId,
        plan: &'a mut LinkPlan<K, Arch, Tls>,
        runtime: &'a RuntimeModuleMemory<R>,
    ) -> Self {
        Self {
            module_id,
            plan,
            runtime,
        }
    }

    pub(crate) fn rewrite(&mut self) -> Result<()> {
        self.rewrite_symbol_tables()?;
        self.rewrite_retained_relocations()?;
        self.rewrite_allocated_relocation_sections()?;
        self.rewrite_dynamic_section()?;
        Ok(())
    }

    fn rewrite_retained_relocations(&mut self) -> Result<()> {
        let relocation_sections = self
            .plan
            .module_layout(self.module_id)
            .relocation_sections()
            .to_vec();

        for relocation_section in relocation_sections {
            self.rewrite_retained_relocation(relocation_section)?;
        }

        Ok(())
    }

    fn rewrite_retained_relocation(&mut self, relocation_section: SectionId) -> Result<()> {
        let metadata = self.plan.section_metadata(relocation_section);
        let symbol_table_section = metadata.linked_section().ok_or_else(|| {
            LinkerError::metadata_rewrite(
                "retained relocation section is missing its linked symbol table",
            )
        })?;
        let target_section = metadata.info_section().ok_or_else(|| {
            LinkerError::metadata_rewrite(
                "retained relocation section is missing its target section",
            )
        })?;
        let runtime = self.runtime;

        let relocation_data = self
            .plan
            .section_data(relocation_section)?
            .as_bytes()
            .to_vec();
        let symbol_data = self
            .plan
            .section_data(symbol_table_section)?
            .as_bytes()
            .to_vec();
        let entries = cast_section_bytes::<ElfRelType<Arch>>(&relocation_data)?;
        let symbols = cast_section_bytes::<ElfSymbol<Arch::Layout>>(&symbol_data)?;
        let ctx = RewriteContext {
            plan: &*self.plan,
            module_id: self.module_id,
            runtime,
        };

        for entry in entries {
            write_retained_relocation::<K, Arch, R, Tls>(&ctx, target_section, entry, symbols)?;
        }

        Ok(())
    }

    fn rewrite_symbol_tables(&mut self) -> Result<()> {
        let sections = self
            .plan
            .module_layout(self.module_id)
            .symbol_table_sections()
            .to_vec();
        let ctx = RewriteContext {
            plan: &*self.plan,
            module_id: self.module_id,
            runtime: self.runtime,
        };
        for section in sections {
            if !ctx.plan.section_metadata(section).is_allocated() {
                continue;
            }
            let count = ctx
                .runtime
                .section_entry_count::<ElfSymbol<Arch::Layout>>(section)?;
            for index in 0..count {
                let mut symbol = self
                    .runtime
                    .read_section_entry::<ElfSymbol<Arch::Layout>>(section, index)?;
                let value = remapped_symbol_value::<K, Arch, R, Tls>(&ctx, &symbol)?;
                symbol.set_value(value);
                ctx.runtime.write_section_entry(section, index, symbol)?;
            }
        }

        Ok(())
    }

    fn rewrite_allocated_relocation_sections(&mut self) -> Result<()> {
        let sections = self
            .plan
            .module_layout(self.module_id)
            .allocated_relocation_sections()
            .to_vec();
        for section in sections {
            let target_section = self.plan.section_metadata(section).info_section();
            let runtime = self.runtime;
            let count = runtime.section_entry_count::<ElfRelType<Arch>>(section)?;
            for index in 0..count {
                let mut rel = runtime.read_section_entry::<ElfRelType<Arch>>(section, index)?;
                let entry_info = RelocationEntryInfo::new::<Arch>(&rel);
                if entry_info.r_type == Arch::NONE {
                    continue;
                }

                let relocation_section =
                    runtime.relocation_section(target_section, entry_info.offset)?;
                let site = runtime.relocation_site(relocation_section)?;
                rel.set_offset(VmOffset::new(site.place.get()));
                let place = runtime.base() + rel.r_offset();
                let mut addend = rel.read_addend(runtime, place)?;
                if entry_info.r_type == Arch::RELATIVE || entry_info.r_type == Arch::IRELATIVE {
                    addend = runtime.remap_relocation_addend(addend)?.1;
                }

                rel.write_addend(runtime, place, addend)?;
                runtime.write_section_entry(section, index, rel)?;
            }
        }

        Ok(())
    }

    fn rewrite_dynamic_section(&mut self) -> Result<()> {
        let Some(dynamic_section) = self.plan.module_layout(self.module_id).dynamic_section()
        else {
            return Ok(());
        };

        let count = self
            .runtime
            .section_entry_count::<ElfDyn<Arch::Layout>>(dynamic_section)?;
        for index in 0..count {
            let mut dyn_ = self
                .runtime
                .read_section_entry::<ElfDyn<Arch::Layout>>(dynamic_section, index)?;
            let tag = dyn_.tag();
            if let Some(value) = self.runtime.remap_dynamic_value(tag, dyn_.value())? {
                dyn_.set_value(value.get());
                self.runtime
                    .write_section_entry(dynamic_section, index, dyn_)?;
            }
            if tag == ElfDynamicTag::NULL {
                break;
            }
        }

        Ok(())
    }
}

fn cast_section_bytes<T: ByteRepr>(bytes: &[u8]) -> Result<&[T]> {
    try_cast_bytes(bytes).ok_or_else(|| {
        LinkerError::metadata_rewrite("section bytes do not match the requested type layout").into()
    })
}

fn write_retained_relocation<K, Arch, R, Tls>(
    ctx: &RewriteContext<'_, K, Arch, R, Tls>,
    target_section: SectionId,
    entry: &ElfRelType<Arch>,
    symbols: &[ElfSymbol<Arch::Layout>],
) -> Result<()>
where
    K: Clone + Ord,
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    <Arch::Layout as ElfLayout>::Word: ByteRepr,
{
    let entry_info = RelocationEntryInfo::new::<Arch>(entry);
    if entry_info.r_type == Arch::NONE {
        return Ok(());
    }

    let relocation_section = ctx
        .runtime
        .relocation_section(Some(target_section), entry_info.offset)?;
    let site = ctx.runtime.relocation_site(relocation_section)?;
    let symbol = symbols.get(entry.r_symbol()).ok_or_else(|| {
        LinkerError::metadata_rewrite("retained relocation references a missing symbol table entry")
    })?;
    let place = ctx.runtime.base() + VmOffset::new(site.place.get());
    let addend = entry.read_addend(ctx.runtime, place)?;
    let symbol_value = retained_relocation_target::<K, Arch, R, Tls>(
        ctx,
        target_section,
        entry,
        symbol,
        &site,
        addend,
    )?;
    let wrote = Cell::new(false);
    let write_bytes = |src: &[u8]| {
        if wrote.replace(true) {
            return Err(LinkerError::metadata_rewrite(
                "relocation value provider called more than one write handler",
            )
            .into());
        }
        ctx.runtime.write_bytes(place, src)
    };

    <Arch as RelocationValueProvider>::relocation_value(
        RelocationValueInput {
            relocation_type: entry.r_type().raw() as usize,
            target: symbol_value,
            addend,
            place: site.place.get(),
        },
        |_| Ok(()),
        |value| write_bytes(&value.get().to_ne_bytes()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
    )
    .map_err(retained_relocation_value_error)?
}

fn retained_relocation_value_error(reason: RelocReason) -> crate::Error {
    LinkerError::metadata_rewrite(match reason {
        RelocReason::IntConversionOutOfRange => "retained relocation value is out of range",
        RelocReason::Unsupported => "retained relocation type is unsupported",
        _ => "retained relocation value computation failed",
    })
    .into()
}

fn remapped_symbol_value<K, Arch, R, Tls>(
    ctx: &RewriteContext<'_, K, Arch, R, Tls>,
    symbol: &ElfSymbol<Arch::Layout>,
) -> Result<usize>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    let symbol_section = match ElfSectionId::from_symbol_shndx(symbol.st_shndx()) {
        Some(scanned_section) => Some(
            ctx.plan
                .module_section_id(ctx.module_id, scanned_section)
                .ok_or_else(|| {
                    LinkerError::metadata_rewrite(
                        "arena-backed symbol value referenced an unmapped section",
                    )
                })?,
        ),
        None => None,
    }
    .filter(|section| ctx.plan.section_metadata(*section).is_allocated());
    ctx.runtime
        .remap_symbol_value(symbol_section, symbol.st_value())
}

fn retained_relocation_target<K, Arch, R, Tls>(
    ctx: &RewriteContext<'_, K, Arch, R, Tls>,
    target_section: SectionId,
    entry: &ElfRelType<Arch>,
    symbol: &ElfSymbol<Arch::Layout>,
    site: &RelocationSite,
    addend: isize,
) -> Result<usize>
where
    K: Clone + Ord,
    Arch: RelocationArch + GotPltTarget,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    let target_bytes = ctx.runtime.read_section_bytes(target_section)?;
    if let Some(source_target) = <Arch as GotPltTarget>::got_plt_target(
        &target_bytes,
        entry.r_type(),
        symbol.is_undef(),
        site.section_offset,
        entry.r_offset().get(),
        addend,
    )? {
        let runtime_target = ctx
            .runtime
            .remap_source_to_runtime_offset(VmOffset::new(source_target))
            .ok_or_else(|| {
                LinkerError::metadata_rewrite(
                    "retained relocation indirect target does not map into arena-backed memory",
                )
            })?;
        return Ok(runtime_target.get());
    }

    remapped_symbol_value(ctx, symbol)
}
