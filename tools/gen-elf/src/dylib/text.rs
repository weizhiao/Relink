use crate::common::SectionKind;
use crate::dylib::{
    reloc::RelocMetaData,
    shdr::{Section, SectionAllocator, SectionHeader, SectionId, ShdrManager},
    symtab::SymTabMetadata,
};
use anyhow::Result;

pub(crate) struct CodeMetaData {
    text_id: SectionId,
    plt_id: SectionId,
    text_size: u64,
    plt_size: u64,
}

pub(crate) struct PatchTextArgs<'a> {
    pub(crate) plt_vaddr: u64,
    pub(crate) text_vaddr: u64,
    pub(crate) got_plt_vaddr: u64,
    pub(crate) resolver_val: u64,
    pub(crate) symtab: &'a SymTabMetadata,
    pub(crate) reloc: &'a RelocMetaData,
    pub(crate) shdr: &'a ShdrManager,
    pub(crate) allocator: &'a mut SectionAllocator,
}

impl CodeMetaData {
    pub(crate) fn new(symtab: &SymTabMetadata, allocator: &mut SectionAllocator) -> Self {
        let text_data = symtab.get_text_content();
        let plt_data = symtab.get_plt_content();
        let text_size = text_data.len() as u64;
        let plt_size = plt_data.len() as u64;
        let text_id = allocator.allocate_with_data(text_data);
        let plt_id = allocator.allocate_with_data(plt_data);
        Self {
            text_id,
            plt_id,
            text_size,
            plt_size,
        }
    }

    pub(crate) fn create_sections(&self, sections: &mut Vec<Section>) {
        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: SectionKind::Text,
                addr: 0,
                offset: 0,
                size: self.text_size,
                addralign: 16,
            },
            data: self.text_id,
        });
        sections.push(Section {
            header: SectionHeader {
                name_off: 0,
                shtype: SectionKind::Plt,
                addr: 0,
                offset: 0,
                size: self.plt_size,
                addralign: 16,
            },
            data: self.plt_id,
        });
    }

    pub(crate) fn patch_text(&mut self, args: PatchTextArgs<'_>) -> Result<()> {
        let text_data = args.allocator.get_mut(&self.text_id);
        // Update IFUNC resolver
        args.symtab
            .patch_ifunc_resolver(text_data, args.text_vaddr, args.resolver_val);

        // Update plt testers
        args.symtab
            .patch_plt_testers(text_data, args.text_vaddr, args.got_plt_vaddr);

        // Update tls testers
        args.symtab.patch_tls_testers(
            text_data,
            args.text_vaddr,
            args.reloc,
            args.shdr,
            args.got_plt_vaddr,
        );

        // Update PLT entries
        let plt_data = args.allocator.get_mut(&self.plt_id);
        args.symtab
            .patch_plt(plt_data, args.plt_vaddr, args.got_plt_vaddr)?;
        Ok(())
    }
}
