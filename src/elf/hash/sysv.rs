//! Traditional SYSV ELF hash table implementation
//!
//! This module implements the traditional SYSV hash table format used in ELF files.
//! While less efficient than the GNU hash table, it is still widely supported and
//! used in many ELF implementations.

use super::ElfHashTable;
use crate::{
    ParseDynamicError, Result,
    elf::{ElfLayout, ElfSymbol, PreCompute, SymbolTable, symbol::SymbolInfo},
    os::{MappedView, TargetAddr},
    segment::ElfSegments,
};
use core::mem::size_of;
/// Header structure for SYSV ELF hash tables
///
/// This structure represents the header of a SYSV hash table, which contains
/// metadata about the hash table structure.
#[repr(C)]
struct ElfHashHeader {
    /// Number of bucket entries in the hash table
    nbucket: u32,

    /// Number of chain entries in the hash table
    nchain: u32,
}

/// SYSV ELF hash table implementation
///
/// This structure represents a SYSV hash table, which uses a bucket/chain
/// structure to organize symbols for efficient lookup.
pub(crate) struct ElfHash {
    /// Hash table header containing metadata
    header: ElfHashHeader,

    /// Bucket array
    buckets: MappedView<u32>,

    /// Chain array
    chains: MappedView<u32>,
}

impl ElfHash {
    /// Parse a SYSV hash table from raw memory
    ///
    /// This method creates an ElfHash instance by parsing the hash table data
    /// from a raw memory pointer.
    ///
    /// # Arguments
    /// * `ptr` - Pointer to the raw hash table data in memory
    ///
    /// # Returns
    /// An ElfHash instance representing the parsed hash table
    #[inline]
    pub(crate) fn parse(segments: &ElfSegments, addr: TargetAddr) -> Result<ElfHash> {
        const HEADER_SIZE: usize = size_of::<ElfHashHeader>();
        let start = addr
            .get()
            .checked_sub(segments.base())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let mut bytes = [0u8; HEADER_SIZE];
        segments.read_bytes(start, &mut bytes)?;
        let header: ElfHashHeader = unsafe { core::mem::transmute(bytes) };

        if header.nbucket == 0 {
            return Err(ParseDynamicError::MalformedHashTable {
                detail: "DT_HASH bucket table is empty",
            }
            .into());
        }

        let bucket_size = (header.nbucket as usize)
            .checked_mul(size_of::<u32>())
            .ok_or(ParseDynamicError::AddressOverflow)?;

        let buckets_off = start
            .checked_add(HEADER_SIZE)
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let chains_off = buckets_off
            .checked_add(bucket_size)
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let buckets = segments.read_view(buckets_off, bucket_size)?.ok_or(
            ParseDynamicError::MalformedHashTable {
                detail: "DT_HASH bucket table size is malformed",
            },
        )?;
        let chain_size = (header.nchain as usize)
            .checked_mul(size_of::<u32>())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let chains = segments.read_view(chains_off, chain_size)?.ok_or(
            ParseDynamicError::MalformedHashTable {
                detail: "DT_HASH chain table size is malformed",
            },
        )?;

        Ok(ElfHash {
            header,
            buckets,
            chains,
        })
    }
}

impl ElfHashTable for ElfHash {
    /// Compute the SYSV hash value for a symbol name
    ///
    /// This method implements the traditional SYSV hash algorithm, which is
    /// used to map symbol names to hash table entries.
    ///
    /// # Arguments
    /// * `name` - The symbol name as a byte slice
    ///
    /// # Returns
    /// The computed hash value
    #[inline]
    fn hash(name: &[u8]) -> u64 {
        let mut hash = 0u32;
        #[allow(unused_assignments)]
        let mut g = 0u32;

        // SYSV hash algorithm
        for byte in name {
            hash = (hash << 4) + u32::from(*byte);
            g = hash & 0xf0000000;
            if g != 0 {
                hash ^= g >> 24;
            }
            hash &= !g;
        }
        hash as u64
    }

    /// Get the number of symbols in the hash table
    ///
    /// # Returns
    /// The number of symbols (chain entries) in the hash table
    #[inline]
    fn count_syms(&self) -> usize {
        self.header.nchain as usize
    }

    /// Look up a symbol in the SYSV hash table
    ///
    /// This method performs a symbol lookup using the bucket/chain structure
    /// of the SYSV hash table.
    ///
    /// # Arguments
    /// * `table` - The symbol table to search in
    /// * `symbol` - Information about the symbol to look up
    /// * `precompute` - Precomputed hash values to speed up the lookup
    ///
    /// # Returns
    /// * `Some(symbol)` - A reference to the found symbol
    /// * `None` - If the symbol was not found
    fn lookup<'sym, L: ElfLayout>(
        table: &'sym SymbolTable<L>,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol<L>> {
        // Get or compute the hash value for the symbol
        let hash = if let Some(hash) = precompute.hash {
            hash
        } else {
            let hash = ElfHash::hash(symbol.name().as_bytes()) as u32;
            precompute.hash = Some(hash);
            hash
        };

        // Get the hash table implementation
        let hashtab = table.hashtab.into_elfhash().unwrap();
        let buckets = hashtab.buckets.as_slice();
        let chains = hashtab.chains.as_slice();

        // Calculate the bucket index and get the first chain index
        let bucket_idx = (hash as usize) % hashtab.header.nbucket as usize;
        let mut chain_idx = *buckets.get(bucket_idx)? as usize;

        // Traverse the chain to find the symbol
        loop {
            // End of chain reached
            if chain_idx == 0 {
                return None;
            }

            // Get the current symbol and its name
            let next_chain = *chains.get(chain_idx)? as usize;
            let cur_symbol = table.symbols.get(chain_idx)?;
            let sym_name = table.strtab.get_str(cur_symbol.st_name());

            // Check if this is the symbol we're looking for
            #[cfg(feature = "version")]
            if sym_name == symbol.name() && table.check_match(chain_idx, symbol.version()) {
                return Some(cur_symbol);
            }
            #[cfg(not(feature = "version"))]
            if sym_name == symbol.name() {
                return Some(cur_symbol);
            }

            // Move to the next entry in the chain
            chain_idx = next_chain;
        }
    }
}
