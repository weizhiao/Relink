use crate::elf::{ElfLayout, ElfShdr, ElfStringTable, ElfSymbol, HashTable, SymbolTable};

impl<L: ElfLayout> SymbolTable<L> {
    /// Creates a symbol table from section headers, typically used for relocatable objects.
    pub(crate) fn from_shdrs(symtab: &ElfShdr<L>, shdrs: &[ElfShdr<L>]) -> Self {
        let strtab_shdr = &shdrs[symtab.sh_link() as usize];
        let strtab = ElfStringTable::new(strtab_shdr.sh_addr() as *const u8);
        let hashtab = HashTable::from_shdr(symtab, &strtab);

        Self {
            hashtab,
            symtab: symtab.sh_addr() as *const ElfSymbol<L>,
            strtab,
            #[cfg(feature = "version")]
            version: None,
        }
    }
}
