use crate::elf::{ElfLayout, ElfSymbol, PreCompute, SymbolTable, symbol::SymbolInfo};

/// A trait for ELF hash table implementations.
///
/// This trait defines the common interface for different ELF symbol hash table
/// implementations. Each implementation must provide methods for computing hash
/// values and looking up symbols.
pub(crate) trait ElfHashTable {
    /// Compute the hash value for a symbol name.
    ///
    /// This method computes a hash value for the given symbol name using the
    /// algorithm specific to the hash table implementation.
    ///
    /// # Arguments
    /// * `name` - The symbol name as a byte slice.
    ///
    /// # Returns
    /// The computed hash value.
    fn hash(name: &[u8]) -> u64;

    /// Get the number of symbols in the hash table.
    ///
    /// # Returns
    /// The number of symbols that can be looked up in this hash table.
    fn count_syms(&self) -> usize;

    /// Look up a symbol in the hash table.
    ///
    /// This method searches for a symbol in the hash table using the provided
    /// symbol information and precomputed hash values.
    ///
    /// # Arguments
    /// * `table` - The symbol table to search in.
    /// * `symbol` - Information about the symbol to look up.
    /// * `precompute` - Precomputed hash values to speed up the lookup.
    ///
    /// # Returns
    /// * `Some(symbol)` - A reference to the found symbol.
    /// * `None` - If the symbol was not found.
    fn lookup<'sym, L: ElfLayout>(
        table: &'sym SymbolTable<L>,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol<L>>;
}
