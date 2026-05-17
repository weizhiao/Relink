use crate::elf::{ElfLayout, ElfShdr, ElfStringTable, HashTable, SymbolTable};

impl<L: ElfLayout> SymbolTable<L> {
    /// Creates a symbol table from section headers, typically used for relocatable objects.
    pub(crate) fn from_shdrs(symtab: &ElfShdr<L>, shdrs: &[ElfShdr<L>]) -> Self {
        let strtab_shdr = &shdrs[symtab.sh_link() as usize];
        let strtab_bytes = unsafe {
            core::slice::from_raw_parts(strtab_shdr.sh_addr() as *const u8, strtab_shdr.sh_size())
        };
        let strtab = ElfStringTable::new(strtab_bytes);
        let hashtab = HashTable::from_shdr(symtab, &strtab);

        Self {
            hashtab,
            symbols: symtab.content(),
            strtab,
            #[cfg(feature = "version")]
            version: None,
        }
    }
}
