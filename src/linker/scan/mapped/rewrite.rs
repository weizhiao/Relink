use super::{RuntimeModuleMemory, RuntimeOffset, RuntimeSectionMemory, SectionId};
use crate::linker::scan::{LinkPlan, MemoryLayoutPlan, ModuleId, SectionMetadata};
use crate::{
    Error, LinkerError, RelocReason, Result,
    aligned_bytes::ByteRepr,
    elf::{
        ElfDyn, ElfDynamicTag, ElfLayout, ElfRelEntry, ElfRelType, ElfRelocationType,
        ElfSectionFlags, ElfSectionId, ElfSymbol, ElfWord,
    },
    memory::{ImageMemory, ImageMemoryExt, RegionAccess, VmAddr, VmOffset},
    relocation::{RelocationArch, RelocationValueInput, RelocationValueProvider},
    tls::TlsResolver,
};
use core::{cell::Cell, mem::size_of};

#[derive(Clone, Copy)]
struct RelocationSection<'a> {
    memory: &'a RuntimeSectionMemory,
    offset: usize,
}

impl RelocationSection<'_> {
    fn place(self) -> Result<RuntimeOffset> {
        self.memory
            .runtime_offset
            .checked_add(self.offset)
            .ok_or_else(|| {
                LinkerError::metadata_rewrite("arena-backed runtime offset overflowed").into()
            })
    }
}

#[derive(Clone, Copy)]
struct RelocationEntryInfo {
    r_type: ElfRelocationType,
    offset: VmOffset,
}

/// Architecture-specific repair of PLT code and retained GOT/PLT references.
pub(crate) trait PltArch {
    fn visit_plt_displacements(
        _section: &SectionMetadata,
        _bytes: &[u8],
        _visit: impl FnMut(usize, i32) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }

    fn got_plt_target(
        _relocation_type: ElfRelocationType,
        _source_place: usize,
        _addend: isize,
        _read_site: impl FnOnce(&mut [u8]) -> Result<()>,
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
        // Callers iterate over the count returned by section_entry_count::<T>.
        let offset = index * size_of::<T>();
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

    fn remap_relocation_addend(&self, addend: isize) -> Result<isize> {
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
        isize::try_from(runtime_offset.get()).map_err(|_| {
            LinkerError::metadata_rewrite("runtime relocation addend should fit in isize").into()
        })
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
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch> = (),
> {
    module_id: ModuleId,
    plan: &'a mut LinkPlan<Arch, Tls>,
    runtime: &'a RuntimeModuleMemory<R>,
}

struct RewriteContext<'a, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch> = ()> {
    plan: &'a LinkPlan<Arch, Tls>,
    module_id: ModuleId,
    runtime: &'a RuntimeModuleMemory<R>,
}

impl<'a, Arch, R, Tls> RuntimeMetadataRewriter<'a, Arch, R, Tls>
where
    Arch: RelocationArch + RelocationValueProvider + PltArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    ElfRelType<Arch>: ByteRepr,
{
    pub(crate) fn new(
        module_id: ModuleId,
        plan: &'a mut LinkPlan<Arch, Tls>,
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
        self.rewrite_plt()?;
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

        self.plan.materialize_section_data(relocation_section)?;
        self.plan.materialize_section_data(symbol_table_section)?;
        let layout = self.plan.memory_layout();
        let entries = section_entries::<ElfRelType<Arch>>(layout, relocation_section)?;
        let symbols = section_entries::<ElfSymbol<Arch::Layout>>(layout, symbol_table_section)?;
        let ctx = RewriteContext {
            plan: &*self.plan,
            module_id: self.module_id,
            runtime,
        };

        for entry in entries {
            write_retained_relocation::<Arch, R, Tls>(&ctx, target_section, entry, symbols)?;
        }

        Ok(())
    }

    fn rewrite_symbol_tables(&self) -> Result<()> {
        let sections = self
            .plan
            .module_layout(self.module_id)
            .symbol_table_sections();
        let ctx = RewriteContext {
            plan: &*self.plan,
            module_id: self.module_id,
            runtime: self.runtime,
        };
        for &section in sections {
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
                let value = remapped_symbol_value::<Arch, R, Tls>(&ctx, &symbol)?;
                symbol.set_value(value);
                ctx.runtime.write_section_entry(section, index, symbol)?;
            }
        }

        Ok(())
    }

    fn rewrite_allocated_relocation_sections(&self) -> Result<()> {
        let sections = self
            .plan
            .module_layout(self.module_id)
            .allocated_relocation_sections();
        for &section in sections {
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
                rel.set_offset(VmOffset::new(relocation_section.place()?.get()));
                let place = runtime.base() + rel.r_offset();
                if entry_info.r_type == Arch::JUMP_SLOT {
                    self.rewrite_jump_slot(place)?;
                } else if entry_info.r_type == Arch::RELATIVE
                    || Arch::IRELATIVE == Some(entry_info.r_type)
                {
                    let addend = rel.read_addend(runtime, place)?;
                    rel.write_addend(runtime, place, runtime.remap_relocation_addend(addend)?)?;
                }
                runtime.write_section_entry(section, index, rel)?;
            }
        }

        Ok(())
    }

    fn rewrite_jump_slot(&self, place: VmAddr) -> Result<()> {
        // Lazy binding later adds the load base to this PLT offset.
        let initial = unsafe {
            self.runtime
                .read_value::<<Arch::Layout as ElfLayout>::Word>(place)?
        };
        if initial.to_usize() == 0 {
            return Ok(());
        }
        let target = self
            .runtime
            .remap_source_to_runtime_offset(VmOffset::new(initial.to_usize()))
            .ok_or_else(|| {
                LinkerError::metadata_rewrite("initial jump slot target is outside placed sections")
            })?;
        unsafe {
            self.runtime.write_value(
                place,
                <Arch::Layout as ElfLayout>::Word::from_usize(target.get()),
            )
        }
    }

    // Static linkers synthesize PLT instructions after producing input relocations.
    // Their references to the GOT need to follow the independently placed sections.
    fn rewrite_plt(&self) -> Result<()> {
        let layout = self.plan.memory_layout();
        for section in &self.runtime.sections {
            let metadata = layout.section(section.section);
            if !metadata
                .section_flags()
                .contains(ElfSectionFlags::EXECINSTR)
            {
                continue;
            }
            let bytes = layout
                .data(section.section)
                .expect("mapped section was populated");
            Arch::visit_plt_displacements(metadata, bytes.as_bytes(), |field, displacement| {
                let next_ip = field + size_of::<i32>();
                let target = section.source_address.get() as i128
                    + next_ip as i128
                    + i128::from(displacement);
                let target = usize::try_from(target)
                    .ok()
                    .and_then(|addr| {
                        self.runtime
                            .remap_source_to_runtime_offset(VmOffset::new(addr))
                    })
                    .ok_or_else(|| {
                        LinkerError::metadata_rewrite("PLT target is outside placed sections")
                    })?;
                let delta =
                    target.get() as i128 - (section.runtime_offset.get() as i128 + next_ip as i128);
                let disp = i32::try_from(delta)
                    .map_err(|_| LinkerError::metadata_rewrite("PLT target is out of reach"))?;
                let addr =
                    self.runtime.base() + VmOffset::new(section.runtime_offset.get() + field);
                self.runtime.write_bytes(addr, &disp.to_le_bytes())
            })?;
        }
        Ok(())
    }

    fn rewrite_dynamic_section(&self) -> Result<()> {
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

fn section_entries<T: ByteRepr>(layout: &MemoryLayoutPlan, section: SectionId) -> Result<&[T]> {
    layout
        .data(section)
        .expect("section was materialized")
        .try_cast_slice()
        .ok_or_else(|| {
            LinkerError::metadata_rewrite("section bytes do not match the requested type layout")
                .into()
        })
}

fn write_retained_relocation<Arch, R, Tls>(
    ctx: &RewriteContext<'_, Arch, R, Tls>,
    target_section: SectionId,
    entry: &ElfRelType<Arch>,
    symbols: &[ElfSymbol<Arch::Layout>],
) -> Result<()>
where
    Arch: RelocationArch + RelocationValueProvider + PltArch,
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
    let offset = relocation_section.place()?;
    let symbol = symbols.get(entry.r_symbol()).ok_or_else(|| {
        LinkerError::metadata_rewrite("retained relocation references a missing symbol table entry")
    })?;
    let place = ctx.runtime.base() + VmOffset::new(offset.get());
    let addend = entry.read_addend(ctx.runtime, place)?;
    let symbol_value =
        retained_relocation_target::<Arch, R, Tls>(ctx, entry, symbol, addend, |bytes| {
            if bytes.len() > relocation_section.memory.size - relocation_section.offset {
                return Err(LinkerError::metadata_rewrite(
                    "retained relocation read range exceeds section",
                )
                .into());
            }
            ctx.runtime.read_bytes(place, bytes)
        })?;
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
            place: offset.get(),
        },
        |_| Ok(()),
        |value| write_bytes(&value.get().to_ne_bytes()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
    )
    .map_err(retained_relocation_value_error)?
}

fn retained_relocation_value_error(reason: RelocReason) -> Error {
    LinkerError::metadata_rewrite(match reason {
        RelocReason::IntConversionOutOfRange => "retained relocation value is out of range",
        RelocReason::Unsupported => "retained relocation type is unsupported",
        _ => "retained relocation value computation failed",
    })
    .into()
}

fn remapped_symbol_value<Arch, R, Tls>(
    ctx: &RewriteContext<'_, Arch, R, Tls>,
    symbol: &ElfSymbol<Arch::Layout>,
) -> Result<usize>
where
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

fn retained_relocation_target<Arch, R, Tls>(
    ctx: &RewriteContext<'_, Arch, R, Tls>,
    entry: &ElfRelType<Arch>,
    symbol: &ElfSymbol<Arch::Layout>,
    addend: isize,
    read_site: impl FnOnce(&mut [u8]) -> Result<()>,
) -> Result<usize>
where
    Arch: RelocationArch + PltArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    if let Some(source_target) = <Arch as PltArch>::got_plt_target(
        entry.r_type(),
        entry.r_offset().get(),
        addend,
        read_site,
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
