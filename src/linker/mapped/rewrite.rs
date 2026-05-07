use super::{RuntimeModuleMemory, RuntimeOffset, RuntimeSectionMemory, SectionId, SourceAddress};
use crate::linker::{
    layout::DataAccess,
    plan::{LinkPlan, ModuleId},
};
use crate::{
    AlignedBytes, LinkerError, Result,
    aligned_bytes::ByteRepr,
    elf::{ElfDyn, ElfDynamicTag, ElfRelType, ElfRelocationType, ElfSymbol},
    image::ScannedSectionId,
    relocation::{RelocationArch, RelocationValueProvider},
};
use core::{cell::Cell, marker::PhantomData, mem::size_of};

#[derive(Clone, Copy)]
struct RelocationSite {
    section: SectionId,
    place: RuntimeOffset,
    section_offset: usize,
    addend: Option<isize>,
}

#[derive(Clone, Copy)]
struct RelocationSection<'a> {
    section: SectionId,
    memory: &'a RuntimeSectionMemory,
    offset: usize,
}

#[derive(Clone, Copy)]
struct RelocationEntryInfo {
    r_type: ElfRelocationType,
    offset: SourceAddress,
    addend: RelocationAddend,
}

#[derive(Clone, Copy)]
enum RelocationAddend {
    #[cfg_attr(any(target_arch = "x86", target_arch = "arm"), allow(dead_code))]
    Explicit(isize),
    #[cfg_attr(not(any(target_arch = "x86", target_arch = "arm")), allow(dead_code))]
    Implicit,
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
    fn new(entry: &ElfRelType) -> Self {
        Self {
            r_type: entry.r_type(),
            offset: SourceAddress::new(entry.r_offset()),
            addend: relocation_addend(entry),
        }
    }
}

impl RuntimeModuleMemory {
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
        if let Some(offset) = section.runtime_offset(SourceAddress::new(value)) {
            return Ok(offset.get());
        }
        Err(LinkerError::metadata_rewrite(
            "arena-backed symbol value does not map into its target section",
        )
        .into())
    }

    fn relocation_site(
        &self,
        section: RelocationSection<'_>,
        entry_info: RelocationEntryInfo,
        addend_bytes: Option<&[u8]>,
    ) -> Result<RelocationSite> {
        let place = section
            .memory
            .runtime_offset
            .checked_add(section.offset)
            .expect("arena-backed runtime offset should not overflow");
        let addend = match entry_info.addend {
            RelocationAddend::Explicit(addend) => Some(addend),
            RelocationAddend::Implicit => addend_bytes
                .map(|bytes| implicit_relocation_addend(bytes, section.offset))
                .transpose()?,
        };

        Ok(RelocationSite {
            section: section.section,
            place,
            section_offset: section.offset,
            addend,
        })
    }

    fn relocation_section(
        &self,
        target: Option<SectionId>,
        source_address: SourceAddress,
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
        source_address: SourceAddress,
    ) -> Result<RelocationSection<'_>> {
        let section = self.section(section_id).ok_or_else(|| {
            LinkerError::metadata_rewrite("relocation target section is not arena-backed")
        })?;
        let offset = section.source_offset(source_address).ok_or_else(|| {
            LinkerError::metadata_rewrite("relocation offset does not map into its target section")
        })?;
        Ok(RelocationSection {
            section: section_id,
            memory: section,
            offset,
        })
    }

    fn addr_to_section(&self, source_address: SourceAddress) -> Option<SectionId> {
        self.sections.iter().find_map(|section| {
            section
                .source_offset(source_address)
                .map(|_| section.section)
        })
    }

    fn remap_relocation_addend(&self, site: RelocationSite) -> Result<(RuntimeOffset, isize)> {
        let source_address = SourceAddress::new(
            usize::try_from(
                site.addend
                    .expect("allocated relocation should carry an addend"),
            )
            .expect("allocated relocation addend should be a source address"),
        );
        let runtime_offset = self
            .remap_source_to_runtime_offset(source_address)
            .expect("allocated relocation addend should map into arena-backed memory");
        let runtime_addend = isize::try_from(runtime_offset.get())
            .expect("runtime relocation addend should fit in isize");

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
                .remap_source_to_runtime_offset(SourceAddress::new(value))
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

pub(crate) struct RuntimeMetadataRewriter<'a, K, Arch: RelocationArch> {
    module_id: ModuleId,
    plan: &'a mut LinkPlan<K>,
    runtime: &'a RuntimeModuleMemory,
    _arch: PhantomData<fn() -> Arch>,
}

impl<'a, K, Arch> RuntimeMetadataRewriter<'a, K, Arch>
where
    K: Clone + Ord,
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
{
    pub(crate) fn new(
        module_id: ModuleId,
        plan: &'a mut LinkPlan<K>,
        runtime: &'a RuntimeModuleMemory,
    ) -> Self {
        Self {
            module_id,
            plan,
            runtime,
            _arch: PhantomData,
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

        self.plan.with_disjoint_section_data(
            [
                (relocation_section, DataAccess::Read),
                (symbol_table_section, DataAccess::Read),
                (target_section, DataAccess::Write),
            ],
            |[relocation_data, symbol_data, target_data]| {
                let relocation_data = relocation_data.into_read();
                let symbol_data = symbol_data.into_read();
                let target_data = target_data.into_write();
                let entries = relocation_data
                    .try_cast_slice::<ElfRelType>()
                    .ok_or_else(|| {
                        LinkerError::metadata_rewrite(
                            "retained relocation section bytes do not match relocation entries",
                        )
                    })?;
                let symbols = symbol_data.try_cast_slice::<ElfSymbol>().ok_or_else(|| {
                    LinkerError::metadata_rewrite(
                        "retained relocation symbol table bytes do not match symbol entries",
                    )
                })?;

                let target_bytes = target_data.as_bytes_mut();

                for entry in entries {
                    write_retained_relocation::<Arch>(
                        runtime,
                        target_section,
                        target_bytes,
                        entry,
                        symbols,
                    )?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }

    fn rewrite_symbol_tables(&mut self) -> Result<()> {
        let sections = self
            .plan
            .module_layout(self.module_id)
            .symbol_table_sections()
            .to_vec();
        for section in sections {
            let module_id = self.module_id;
            let runtime = self.runtime;
            self.plan.for_each_section_data::<ElfSymbol, _>(
                section,
                |symbol, plan| {
                    let symbol_section =
                        match ScannedSectionId::from_symbol_shndx(symbol.st_shndx()) {
                            Some(scanned_section) => Some(
                                plan.section_id(module_id, scanned_section).ok_or_else(|| {
                                    LinkerError::metadata_rewrite(
                                        "arena-backed symbol value referenced an unmapped section",
                                    )
                                })?,
                            ),
                            None => None,
                        }
                        .filter(|section| plan.section(*section).is_allocated());
                    runtime
                        .remap_symbol_value(symbol_section, symbol.st_value())
                        .map(Some)
                },
                |plan, index, value| {
                    let data = plan.section_data_mut(section)?;
                    let symbols = cast_section_slice_mut::<ElfSymbol>(data)?;
                    let symbol = symbols
                        .get_mut(index)
                        .expect("symbol table entry index should remain valid");
                    symbol.set_value(value);
                    Ok(())
                },
            )?;
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
            self.plan.for_each_section_data::<ElfRelType, _>(
                section,
                |entry, _| {
                    let entry_info = RelocationEntryInfo::new(entry);
                    if entry_info.r_type == Arch::NONE {
                        return Ok(None);
                    }

                    let relocation_section =
                        runtime.relocation_section(target_section, entry_info.offset)?;
                    let site = runtime.relocation_site(relocation_section, entry_info, None)?;
                    Ok(Some((entry_info, site)))
                },
                |plan, index, (entry_info, mut site)| {
                    if site.addend.is_none() {
                        return plan.with_disjoint_section_data(
                            [
                                (section, DataAccess::Write),
                                (site.section, DataAccess::Write),
                            ],
                            |[relocation_data, site_data]| {
                                let relocation_data = relocation_data.into_write();
                                let site_data = site_data.into_write();
                                site.addend = Some(implicit_relocation_addend(
                                    site_data.as_bytes(),
                                    site.section_offset,
                                )?);
                                if entry_info.r_type == Arch::RELATIVE
                                    || entry_info.r_type == Arch::IRELATIVE
                                {
                                    let (runtime_offset, runtime_addend) =
                                        runtime.remap_relocation_addend(site)?;
                                    write_runtime_relocation_addend(
                                        site_data,
                                        site,
                                        runtime_offset,
                                    )?;
                                    site.addend = Some(runtime_addend);
                                }
                                rewrite_allocated_relocation_entry(relocation_data, index, site)
                            },
                        );
                    }
                    if entry_info.r_type == Arch::RELATIVE || entry_info.r_type == Arch::IRELATIVE {
                        site.addend = Some(runtime.remap_relocation_addend(site)?.1);
                    }
                    let data = plan.section_data_mut(section)?;
                    rewrite_allocated_relocation_entry(data, index, site)?;
                    Ok(())
                },
            )?;
        }

        Ok(())
    }

    fn rewrite_dynamic_section(&mut self) -> Result<()> {
        let Some(dynamic_section) = self.plan.module_layout(self.module_id).dynamic_section()
        else {
            return Ok(());
        };

        let data = self.plan.section_data_mut(dynamic_section)?;
        let dyns = cast_section_slice_mut::<ElfDyn>(data)?;

        for dyn_ in dyns.iter_mut() {
            let tag = dyn_.tag();
            if let Some(value) = self.runtime.remap_dynamic_value(tag, dyn_.value())? {
                dyn_.set_value(value.get());
            }
            if tag == ElfDynamicTag::NULL {
                break;
            }
        }

        Ok(())
    }
}

fn rewrite_allocated_relocation_entry(
    data: &mut AlignedBytes,
    index: usize,
    site: RelocationSite,
) -> Result<()> {
    let entries = cast_section_slice_mut::<ElfRelType>(data)?;
    let rel = entries
        .get_mut(index)
        .expect("allocated relocation entry index should remain valid");
    #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
    if let Some(addend) = site.addend {
        rel.set_addend(0, addend);
    }
    rel.set_offset(site.place.get());
    Ok(())
}

fn write_runtime_relocation_addend(
    data: &mut AlignedBytes,
    site: RelocationSite,
    addend: RuntimeOffset,
) -> Result<()> {
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    {
        let end = site
            .section_offset
            .checked_add(size_of::<usize>())
            .expect("allocated relocation addend range should not overflow");
        let bytes = data
            .as_bytes_mut()
            .get_mut(site.section_offset..end)
            .expect("allocated relocation addend should fit in its target section");
        bytes.copy_from_slice(&addend.get().to_ne_bytes());
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
    let _ = (data, site.section_offset, addend);

    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
fn relocation_addend(rel: &ElfRelType) -> RelocationAddend {
    RelocationAddend::Explicit(rel.r_addend(0))
}

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
fn relocation_addend(_rel: &ElfRelType) -> RelocationAddend {
    RelocationAddend::Implicit
}

fn implicit_relocation_addend(bytes: &[u8], section_offset: usize) -> Result<isize> {
    let end = section_offset
        .checked_add(size_of::<usize>())
        .expect("relocation addend range should not overflow");
    let bytes = bytes
        .get(section_offset..end)
        .ok_or_else(|| LinkerError::metadata_rewrite("relocation addend range exceeds section"))?;
    let mut addend = [0u8; size_of::<usize>()];
    addend.copy_from_slice(bytes);
    Ok(usize::from_ne_bytes(addend) as isize)
}

fn cast_section_slice_mut<T: ByteRepr>(data: &mut AlignedBytes) -> Result<&mut [T]> {
    data.try_cast_slice_mut::<T>().ok_or_else(|| {
        LinkerError::metadata_rewrite("section bytes do not match the requested type layout").into()
    })
}

fn write_retained_relocation<Arch>(
    runtime: &RuntimeModuleMemory,
    target_section: SectionId,
    target_bytes: &mut [u8],
    entry: &ElfRelType,
    symbols: &[ElfSymbol],
) -> Result<()>
where
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
{
    let entry_info = RelocationEntryInfo::new(entry);
    if entry_info.r_type == Arch::NONE {
        return Ok(());
    }

    let relocation_section = runtime.relocation_section(Some(target_section), entry_info.offset)?;
    let site = runtime.relocation_site(relocation_section, entry_info, Some(target_bytes))?;
    let symbol = symbols.get(entry.r_symbol()).ok_or_else(|| {
        LinkerError::metadata_rewrite("retained relocation references a missing symbol table entry")
    })?;
    let addend = site
        .addend
        .expect("retained relocation site should carry an addend");
    let symbol_value =
        retained_relocation_target::<Arch>(runtime, target_bytes, entry, symbol, &site, addend)?;
    let section_bytes = Cell::new(Some(target_bytes));
    let write_bytes = |src: &[u8]| {
        let section_bytes = section_bytes
            .take()
            .expect("relocation value provider called more than one write handler");
        let end = site.section_offset.checked_add(src.len()).ok_or_else(|| {
            LinkerError::metadata_rewrite("retained relocation write range overflowed")
        })?;
        let dst = section_bytes
            .get_mut(site.section_offset..end)
            .ok_or_else(|| {
                LinkerError::metadata_rewrite("retained relocation write range exceeds section")
            })?;
        dst.copy_from_slice(src);
        Ok(())
    };

    <Arch as RelocationValueProvider>::relocation_value(
        entry.r_type().raw() as usize,
        symbol_value,
        addend,
        site.place.get(),
        |_| Ok(()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
    )?
}

fn retained_relocation_target<Arch>(
    runtime: &RuntimeModuleMemory,
    target_bytes: &[u8],
    entry: &ElfRelType,
    symbol: &ElfSymbol,
    site: &RelocationSite,
    addend: isize,
) -> Result<usize>
where
    Arch: RelocationArch + GotPltTarget,
{
    if let Some(source_target) = <Arch as GotPltTarget>::got_plt_target(
        target_bytes,
        entry.r_type(),
        symbol.is_undef(),
        site.section_offset,
        entry.r_offset(),
        addend,
    )? {
        let runtime_target = runtime
            .remap_source_to_runtime_offset(SourceAddress::new(source_target))
            .ok_or_else(|| {
                LinkerError::metadata_rewrite(
                    "retained relocation indirect target does not map into arena-backed memory",
                )
            })?;
        return Ok(runtime_target.get());
    }

    // Symbol tables are rewritten first, so st_value is already in
    // arena-backed runtime coordinates here.
    Ok(symbol.st_value())
}
