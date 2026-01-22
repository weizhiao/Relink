use crate::common::SectionKind;
use crate::dylib::{
    reloc::RelocMetaData,
    shdr::{Section, SectionAllocator, SectionHeader, SectionId, ShdrManager},
    symtab::SymTabMetadata,
};

pub(crate) struct CodeMetaData {
    text_id: SectionId,
    plt_id: SectionId,
    text_size: u64,
    plt_size: u64,
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
            data: self.text_id.clone(),
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
            data: self.plt_id.clone(),
        });
    }

    pub(crate) fn patch_text(
        &mut self,
        plt_vaddr: u64,
        text_vaddr: u64,
        got_plt_vaddr: u64,
        resolver_val: u64,
        symtab: &SymTabMetadata,
        reloc: &RelocMetaData,
        shdr: &ShdrManager,
        allocator: &mut SectionAllocator,
    ) {
        let text_data = allocator.get_mut(&self.text_id);
        // Update IFUNC resolver
        symtab.patch_ifunc_resolver(text_data, text_vaddr, resolver_val);

        // Update plt testers
        symtab.patch_plt_testers(text_data, text_vaddr, got_plt_vaddr);

        // Update tls testers
        symtab.patch_tls_testers(text_data, text_vaddr, reloc, shdr, got_plt_vaddr);

        // Update PLT entries
        let plt_data = allocator.get_mut(&self.plt_id);
        symtab.patch_plt(plt_data, plt_vaddr, got_plt_vaddr);
    }
}
