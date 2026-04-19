use super::{
    LayoutSectionId, MappedArenaMap, MemoryLayoutPlan, RuntimeModuleMemory, RuntimeSectionMemory,
    build_runtime_memory,
};
use crate::linker::plan::{LinkModuleId, LinkPlan};
use crate::{
    Result,
    arch::{Architecture, REL_NONE},
    elf::{ElfDyn, ElfDynamicTag, ElfRelType, ElfSymbol},
    image::ScannedSectionId,
};
use alloc::vec::Vec;
use core::cell::Cell;

struct RuntimeRelocationSite {
    place: usize,
    section_offset: usize,
}

impl RuntimeModuleMemory {
    fn section(&self, section: LayoutSectionId) -> Option<RuntimeSectionMemory> {
        self.sections
            .iter()
            .copied()
            .find(|runtime_section| runtime_section.section == section)
    }

    fn remap_symbol_value(&self, section: Option<LayoutSectionId>, value: usize) -> Result<usize> {
        let Some(section_id) = section else {
            return Ok(value);
        };
        let Some(section) = self.section(section_id) else {
            return Err(crate::custom_error(
                "arena-backed symbol value referenced an unplaced section",
            ));
        };
        if let Some(offset) = section.source_offset(value) {
            return Ok(section.runtime_offset + offset);
        }
        Err(crate::custom_error(
            "arena-backed symbol value does not map into its target section",
        ))
    }

    fn remap_relocation_offset(
        &self,
        target: Option<LayoutSectionId>,
        original_offset: usize,
    ) -> Result<usize> {
        if let Some(section) = target {
            let Some(section) = self.section(section) else {
                return Err(crate::custom_error(
                    "allocated relocation entry target section is not arena-backed",
                ));
            };
            if let Some(offset) = section.source_offset(original_offset) {
                return Ok(section.runtime_offset + offset);
            }

            return Err(crate::custom_error(
                "allocated relocation entry offset does not map into its target section",
            ));
        }

        self.remap_source_address(original_offset)?.ok_or_else(|| {
            crate::custom_error(
                "allocated relocation entry offset does not map into arena-backed memory",
            )
        })
    }

    fn remap_dynamic_value(&self, tag: ElfDynamicTag, value: usize) -> Result<Option<usize>> {
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
            | ElfDynamicTag::VERDEF => self.remap_source_address(value),
            _ => Ok(None),
        }
    }

    fn retained_relocation_site(
        &self,
        target_section: LayoutSectionId,
        source_address: usize,
    ) -> Result<RuntimeRelocationSite> {
        let section = self.section(target_section).ok_or_else(|| {
            crate::custom_error("retained relocation target section is not arena-backed")
        })?;
        let section_offset = section.source_offset(source_address).ok_or_else(|| {
            crate::custom_error("retained relocation offset does not map into its target section")
        })?;
        let place = section
            .runtime_offset
            .checked_add(section_offset)
            .ok_or_else(|| crate::custom_error("arena-backed runtime offset overflowed"))?;

        Ok(RuntimeRelocationSite {
            place,
            section_offset,
        })
    }
}

struct RuntimeMetadataRewriter<'a, K, D: 'static> {
    module_id: LinkModuleId,
    plan: &'a mut LinkPlan<K, D>,
    runtime: &'a RuntimeModuleMemory,
}

impl<'a, K, D> RuntimeMetadataRewriter<'a, K, D>
where
    K: Clone + Ord,
    D: 'static,
{
    fn new(
        module_id: LinkModuleId,
        plan: &'a mut LinkPlan<K, D>,
        runtime: &'a RuntimeModuleMemory,
    ) -> Self {
        Self {
            module_id,
            plan,
            runtime,
        }
    }

    fn rewrite(&mut self) -> Result<()> {
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
            self.rewrite_retained_relocation_section(relocation_section)?;
        }

        Ok(())
    }

    fn rewrite_retained_relocation_section(
        &mut self,
        relocation_section: LayoutSectionId,
    ) -> Result<()> {
        let metadata = self.plan.section_metadata(relocation_section);
        let symbol_table_section = metadata.linked_section().ok_or_else(|| {
            crate::custom_error("retained relocation section is missing its linked symbol table")
        })?;

        let target_section = metadata.info_section().ok_or_else(|| {
            crate::custom_error("retained relocation section is missing its target section")
        })?;
        let runtime = self.runtime;

        self.plan.with_disjoint_section_data_mut(
            relocation_section,
            symbol_table_section,
            target_section,
            |relocation_data, symbol_data, target_data| {
                let entries = relocation_data
                    .try_cast_slice::<ElfRelType>()
                    .ok_or_else(|| {
                        crate::custom_error(
                            "retained relocation section bytes do not match relocation entries",
                        )
                    })?;
                let symbols = symbol_data.try_cast_slice::<ElfSymbol>().ok_or_else(|| {
                    crate::custom_error(
                        "retained relocation symbol table bytes do not match symbol entries",
                    )
                })?;

                let target_bytes = target_data.as_bytes_mut();

                for entry in entries {
                    write_retained_relocation(
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
            let symbol_sections = {
                let (data, layout) = self.plan.section_data_with_layout(section)?;
                let mut symbol_sections = Vec::new();
                data.try_for_each(|_, symbol: &ElfSymbol| -> Result<()> {
                    let symbol_section =
                        symbol_section_id(self.module_id, layout, symbol.st_shndx())?;
                    symbol_sections.push(symbol_section);
                    Ok(())
                })
                .ok_or_else(|| {
                    crate::custom_error("section bytes do not match the requested type layout")
                })??;
                symbol_sections
            };

            let data = self.plan.section_data_mut(section)?;
            data.try_for_each_mut(|index, symbol: &mut ElfSymbol| -> Result<()> {
                let symbol_section = symbol_sections[index];
                let value = self
                    .runtime
                    .remap_symbol_value(symbol_section, symbol.st_value())?;
                symbol.set_value(value);
                Ok(())
            })
            .ok_or_else(|| {
                crate::custom_error("section bytes do not match the requested type layout")
            })??;
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
            let relocation = self.plan.section_metadata(section).info_section();
            let data = self.plan.section_data_mut(section)?;
            data.try_for_each_mut(|_, rel: &mut ElfRelType| -> Result<()> {
                if rel.r_type() as u32 == REL_NONE {
                    return Ok(());
                }
                let offset = self
                    .runtime
                    .remap_relocation_offset(relocation, rel.r_offset())?;
                rel.set_offset(offset);
                Ok(())
            })
            .ok_or_else(|| {
                crate::custom_error("section bytes do not match the requested type layout")
            })??;
        }

        Ok(())
    }

    fn rewrite_dynamic_section(&mut self) -> Result<()> {
        let Some(dynamic_section) = self.plan.module_layout(self.module_id).dynamic_section()
        else {
            return Ok(());
        };

        let data = self.plan.section_data_mut(dynamic_section)?;
        let dyns = data.try_cast_slice_mut::<ElfDyn>().ok_or_else(|| {
            crate::custom_error("section bytes do not match the requested type layout")
        })?;

        for dyn_ in dyns.iter_mut() {
            let tag = dyn_.tag();
            if let Some(value) = self.runtime.remap_dynamic_value(tag, dyn_.value())? {
                dyn_.set_value(value);
            }
            if tag == ElfDynamicTag::NULL {
                break;
            }
        }

        Ok(())
    }
}

pub(crate) fn repair_arena_layout_module<K, D>(
    module_id: LinkModuleId,
    plan: &mut LinkPlan<K, D>,
    mapped_section_arenas: &MappedArenaMap,
) -> Result<()>
where
    K: Clone + Ord,
    D: 'static,
{
    let runtime = build_runtime_memory(module_id, plan.memory_layout(), mapped_section_arenas)?;
    let mut rewriter = RuntimeMetadataRewriter::new(module_id, plan, &runtime);
    rewriter.rewrite()
}

fn symbol_section_id(
    module_id: LinkModuleId,
    layout: &MemoryLayoutPlan,
    section_index: usize,
) -> Result<Option<LayoutSectionId>> {
    if section_index == elf::abi::SHN_UNDEF as usize || section_index == elf::abi::SHN_ABS as usize
    {
        return Ok(None);
    }

    layout
        .module_section_id(module_id, ScannedSectionId::new(section_index))
        .map(Some)
        .ok_or_else(|| {
            crate::custom_error("arena-backed symbol value referenced an unmapped section")
        })
}

fn write_retained_relocation(
    runtime: &RuntimeModuleMemory,
    target_section: LayoutSectionId,
    target_bytes: &mut [u8],
    entry: &ElfRelType,
    symbols: &[ElfSymbol],
) -> Result<()> {
    if entry.r_type() as u32 == REL_NONE {
        return Ok(());
    }

    let site = runtime.retained_relocation_site(target_section, entry.r_offset())?;
    let symbol = symbols.get(entry.r_symbol()).ok_or_else(|| {
        crate::custom_error("retained relocation references a missing symbol table entry")
    })?;
    // Symbol tables are rewritten first, so st_value is already in
    // arena-backed runtime coordinates here.
    let symbol_value = symbol.st_value();
    let addend = retained_relocation_addend(entry)?;
    let section_bytes = Cell::new(Some(target_bytes));
    let write_bytes = |src: &[u8]| {
        let section_bytes = section_bytes
            .take()
            .expect("relocation value provider called more than one write handler");
        let end = site
            .section_offset
            .checked_add(src.len())
            .ok_or_else(|| crate::custom_error("retained relocation write range overflowed"))?;
        let dst = section_bytes
            .get_mut(site.section_offset..end)
            .ok_or_else(|| {
                crate::custom_error("retained relocation write range exceeds section")
            })?;
        dst.copy_from_slice(src);
        Ok(())
    };

    <Architecture as crate::relocation::RelocationValueProvider>::relocation_value(
        entry.r_type(),
        symbol_value,
        addend,
        site.place,
        |_| Ok(()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
        |value| write_bytes(&value.into_inner().to_ne_bytes()),
    )?
}

fn retained_relocation_addend(entry: &ElfRelType) -> Result<isize> {
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    {
        let _ = entry;
        Err(crate::custom_error(
            "arena-backed retained relocation repair requires explicit relocation addends",
        ))
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
    {
        Ok(entry.r_addend(0))
    }
}
