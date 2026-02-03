use crate::dylib::{ElfWriterConfig, align_up};

pub(crate) struct ElfLayout {
    pub(crate) base_addr: u64,
    pub(crate) page_size: u64,
    pub(crate) file_off: u64,
}

impl ElfLayout {
    pub(crate) fn new(config: &ElfWriterConfig) -> Self {
        Self {
            base_addr: config.base_addr,
            page_size: config.page_size,
            file_off: 0,
        }
    }

    pub(crate) fn add_header(&mut self, ehdr_size: u64, ph_size: u64) {
        self.file_off = ehdr_size + ph_size;
        self.align_to_page();
    }

    pub(crate) fn align_to_page(&mut self) {
        self.file_off = align_up(self.file_off, self.page_size);
    }

    pub(crate) fn add_section(&mut self, size: u64, align: u64) -> (u64, u64) {
        self.file_off = align_up(self.file_off, align);
        let offset = self.file_off;
        let vaddr = self.base_addr + offset;
        self.file_off += size;
        (offset, vaddr)
    }
}
