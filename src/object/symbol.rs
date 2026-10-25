use crate::Result;
use crate::elf::{ElfLayout, ElfShdr, ElfStringTable, ElfSymbol, SymbolTableView};
use crate::memory::{ImageMemory, MappedView};
use crate::object::{section_bytes, section_entries_mut};
use core::fmt::Debug;

/// Relocation workspace for relocatable-object symbols.
pub(crate) struct ObjectSymbolTable<L: ElfLayout> {
    symbols: &'static mut [ElfSymbol<L>],
    strtab: ElfStringTable,
}

impl<L: ElfLayout> Debug for ObjectSymbolTable<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectSymbolTable")
            .field("symbol_count", &self.symbols.len())
            .finish()
    }
}

impl<L: ElfLayout> ObjectSymbolTable<L> {
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
        Ok(Self { symbols, strtab })
    }

    #[inline]
    pub(crate) fn view(&self) -> SymbolTableView<'_, L> {
        SymbolTableView {
            symbols: self.symbols,
            strtab: &self.strtab,
            #[cfg(feature = "version")]
            version: None,
        }
    }

    #[inline]
    pub(crate) fn symbols(&self) -> &[ElfSymbol<L>] {
        self.symbols
    }

    #[inline]
    pub(crate) fn symbols_mut(&mut self) -> &mut [ElfSymbol<L>] {
        self.symbols
    }
}
