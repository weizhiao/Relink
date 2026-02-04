use crate::common::SectionKind;
use crate::dylib::{
    reloc::RelocMetaData,
    shdr::{Section, SectionAllocator, SectionHeader, SectionId},
    symtab::SymTabMetadata,
};

pub(crate) struct DataMetaData {
    data_id: SectionId,
    data_size: u64,
}

impl DataMetaData {
    pub(crate) fn new(
        reloc: &RelocMetaData,
        symtab: &SymTabMetadata,
        allocator: &mut SectionAllocator,
    ) -> Self {
        let mut data_content = symtab.get_data_content();
        // Allocate extra space for COPY relocations in .data section
        let copy_size = reloc.total_copy_size();
        if copy_size > 0 {
            data_content.resize(data_content.len() + copy_size as usize, 0);
        }
        let data_size = data_content.len() as u64;
        let data_id = allocator.allocate_with_data(data_content);
        Self { data_id, data_size }
    }

    pub(crate) fn create_sections(&self, sections: &mut Vec<Section>) {
        let data = SectionHeader {
            name_off: 0,
            shtype: SectionKind::Data,
            addr: 0,
            offset: 0,
            size: self.data_size,
            addralign: 8,
        };
        sections.push(Section {
            header: data,
            data: self.data_id,
        });
    }
}
