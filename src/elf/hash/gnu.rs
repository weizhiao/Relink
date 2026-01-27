//! GNU ELF hash table implementation
//!
//! This module implements the GNU hash table format used in modern ELF files.
//! The GNU hash table provides better performance and memory efficiency compared
//! to the traditional SYSV hash table.

use super::ElfHashTable;
use crate::{
    elf::ElfSymbol,
    elf::{PreCompute, SymbolTable, symbol::SymbolInfo},
};

/// Header structure for GNU ELF hash tables
///
/// This structure represents the header of a GNU hash table, which contains
/// metadata about the hash table structure and layout.
#[repr(C)]
struct ElfGnuHeader {
    /// Number of bucket entries in the hash table
    nbucket: u32,

    /// Symbol bias - index of the first symbol in the hash table
    symbias: u32,

    /// Number of bloom filter entries
    nbloom: u32,

    /// Shift count used in bloom filter operations
    nshift: u32,
}

/// GNU ELF hash table implementation
///
/// This structure represents a GNU hash table, which uses an optimized structure
/// with bloom filters, buckets, and chains to provide efficient symbol lookup.
pub(crate) struct ElfGnuHash {
    /// Hash table header containing metadata
    header: ElfGnuHeader,

    /// Pointer to the bloom filter array
    blooms: *const usize,

    /// Pointer to the bucket array
    buckets: *const u32,

    /// Pointer to the chain array
    chains: *const u32,
}

impl ElfGnuHash {
    /// Parse a GNU hash table from raw memory
    ///
    /// This method creates an ElfGnuHash instance by parsing the hash table data
    /// from a raw memory pointer.
    ///
    /// # Arguments
    /// * `ptr` - Pointer to the raw hash table data in memory
    ///
    /// # Returns
    /// An ElfGnuHash instance representing the parsed hash table
    #[inline]
    pub(crate) fn parse(ptr: *const u8) -> ElfGnuHash {
        const HEADER_SIZE: usize = size_of::<ElfGnuHeader>();
        let mut bytes = [0u8; HEADER_SIZE];
        bytes.copy_from_slice(unsafe { core::slice::from_raw_parts(ptr, HEADER_SIZE) });
        let header: ElfGnuHeader = unsafe { core::mem::transmute(bytes) };

        // Calculate the sizes of each section
        let bloom_size = header.nbloom as usize * size_of::<usize>();
        let bucket_size = header.nbucket as usize * size_of::<u32>();

        // Calculate pointers to each section
        let blooms = unsafe { ptr.add(HEADER_SIZE) };
        let buckets = unsafe { blooms.add(bloom_size) };
        let chains = unsafe { buckets.add(bucket_size) };

        ElfGnuHash {
            header,
            blooms: blooms.cast(),
            buckets: buckets.cast(),
            chains: chains.cast(),
        }
    }
}

impl ElfHashTable for ElfGnuHash {
    /// Compute the GNU hash value for a symbol name
    ///
    /// This method implements the GNU hash algorithm, which is based on
    /// the djb2 hash function and provides good distribution properties.
    ///
    /// # Arguments
    /// * `name` - The symbol name as a byte slice
    ///
    /// # Returns
    /// The computed hash value
    #[inline]
    fn hash(name: &[u8]) -> u64 {
        let mut hash = 5381u32; // Initial value for djb2 hash

        // GNU hash algorithm (djb2 variant)
        for byte in name {
            hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
        }
        hash as u64
    }

    /// Get the number of symbols in the hash table
    ///
    /// This method calculates the number of symbols by examining the bucket
    /// and chain arrays to determine the highest symbol index.
    ///
    /// # Returns
    /// The number of symbols in the hash table
    fn count_syms(&self) -> usize {
        let mut nsym = 0;

        // Find the maximum symbol index referenced by buckets
        for i in 0..self.header.nbucket as usize {
            nsym = nsym.max(unsafe { self.buckets.add(i).read() as usize });
        }

        // If we found a valid symbol index, check the chains for the end marker
        if nsym > 0 {
            unsafe {
                let mut val = self.chains.add(nsym - self.header.symbias as usize);
                // Find the end of the chain (marked by LSB = 1)
                while val.read() & 1 == 0 {
                    nsym += 1;
                    val = val.add(1);
                }
            }
        }

        // Return the count (nsym + 1 to include the last symbol)
        nsym + 1
    }

    /// Look up a symbol in the GNU hash table
    ///
    /// This method performs a symbol lookup using the optimized GNU hash table
    /// structure, which includes bloom filters for fast negative lookups.
    ///
    /// # Arguments
    /// * `table` - The symbol table to search in
    /// * `symbol` - Information about the symbol to look up
    /// * `precompute` - Precomputed hash values to speed up the lookup
    ///
    /// # Returns
    /// * `Some(symbol)` - A reference to the found symbol
    /// * `None` - If the symbol was not found
    fn lookup<'sym>(
        table: &'sym SymbolTable,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol> {
        // Get precomputed hash values
        let hash = precompute.gnuhash;
        let fofs = precompute.fofs;
        let fmask = precompute.fmask;

        // Get the hash table implementation
        let hashtab = table.hashtab.into_gnuhash().unwrap();

        // Check bloom filter for fast negative lookup
        let bloom_idx = fofs & (hashtab.header.nbloom - 1) as usize;
        let filter = unsafe { hashtab.blooms.add(bloom_idx).read() };

        // First bloom filter check
        if filter & fmask == 0 {
            return None;
        }

        // Second bloom filter check
        let filter2 = filter >> ((hash >> hashtab.header.nshift) as usize % usize::BITS as usize);
        if filter2 & 1 == 0 {
            return None;
        }

        // Bloom filters passed, now check the actual hash chains
        let table_start_idx = hashtab.header.symbias as usize;
        let chain_start_idx = unsafe {
            hashtab
                .buckets
                .add((hash as usize) % hashtab.header.nbucket as usize)
                .read()
        } as usize;

        // If bucket is empty, symbol is not present
        if chain_start_idx == 0 {
            return None;
        }

        // Traverse the chain to find the symbol
        #[cfg(feature = "version")]
        let mut dynsym_idx = chain_start_idx;
        let mut cur_chain = unsafe { hashtab.chains.add(chain_start_idx - table_start_idx) };
        let mut cur_symbol_ptr = unsafe { table.symtab.add(chain_start_idx) };

        loop {
            let chain_hash = unsafe { cur_chain.read() };

            // Check if this chain entry matches our hash (ignoring LSB)
            if hash | 1 == chain_hash | 1 {
                let cur_symbol = unsafe { &*cur_symbol_ptr };
                let sym_name = table.strtab.get_str(cur_symbol.st_name());

                // Check if this is the symbol we're looking for
                #[cfg(feature = "version")]
                if sym_name == symbol.name() && table.check_match(dynsym_idx, symbol.version()) {
                    return Some(cur_symbol);
                }
                #[cfg(not(feature = "version"))]
                if sym_name == symbol.name() {
                    return Some(cur_symbol);
                }
            }

            // Check if we've reached the end of the chain (LSB = 1 indicates end)
            if chain_hash & 1 != 0 {
                break;
            }

            // Move to the next entry in the chain
            cur_chain = unsafe { cur_chain.add(1) };
            cur_symbol_ptr = unsafe { cur_symbol_ptr.add(1) };
            #[cfg(feature = "version")]
            {
                dynsym_idx += 1;
            }
        }

        // Symbol not found in the chain
        None
    }
}
