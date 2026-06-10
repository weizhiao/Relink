use crate::Result;
use crate::elf::{ElfLayout, ElfShdr, ElfStringTable, SymbolStorage, SymbolTable};
use crate::object::{CustomHash, section_bytes, section_entries_mut};
use crate::os::{ImageMemory, MappedView};

static EMPTY_STRTAB: [u8; 1] = [0];

impl<L: ElfLayout> SymbolTable<L, CustomHash> {
    pub(crate) fn empty_object() -> Self {
        Self {
            hashtab: CustomHash::empty(),
            symbols: SymbolStorage::borrowed(&[]),
            strtab: ElfStringTable::new(MappedView::from_slice(&EMPTY_STRTAB)),
            #[cfg(feature = "version")]
            version: None,
        }
    }

    /// Creates a symbol table from section headers, typically used for relocatable objects.
    pub(crate) fn from_shdrs<Memory>(
        symtab: &ElfShdr<L>,
        shdrs: &[ElfShdr<L>],
        memory: &Memory,
    ) -> Result<Self>
    where
        Memory: ImageMemory + ?Sized,
    {
        let strtab_shdr = &shdrs[symtab.sh_link() as usize];
        let strtab_bytes = section_bytes(memory, strtab_shdr)?;
        let strtab = ElfStringTable::new(MappedView::from_slice(strtab_bytes));
        let symbols = section_entries_mut(memory, symtab)?;
        let hashtab = CustomHash::from_symbols(&*symbols, &strtab);

        Ok(Self {
            hashtab,
            symbols: SymbolStorage::mutable(symbols),
            strtab,
            #[cfg(feature = "version")]
            version: None,
        })
    }
}
