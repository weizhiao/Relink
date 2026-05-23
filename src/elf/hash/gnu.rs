//! GNU ELF hash table implementation
//!
//! This module implements the GNU hash table format used in modern ELF files.
//! The GNU hash table provides better performance and memory efficiency compared
//! to the traditional SYSV hash table.

use super::ElfHashTable;
use crate::{
    ParseDynamicError, Result,
    elf::{ElfLayout, ElfSymbol, ElfWord},
    elf::{PreCompute, SymbolTable, symbol::SymbolInfo},
    os::{MappedView, RegionAccess, VmAddr, VmOffset},
    segment::ElfSegments,
};
use core::mem::size_of;

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
pub(crate) struct ElfGnuHash<L: ElfLayout> {
    /// Hash table header containing metadata
    header: ElfGnuHeader,

    /// Bloom filter array
    blooms: MappedView<L::Word>,

    /// Bucket array
    buckets: MappedView<u32>,

    /// Chain array
    chains: MappedView<u32>,
}

impl<L: ElfLayout> ElfGnuHash<L> {
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
    pub(crate) fn parse<R: RegionAccess>(segments: &ElfSegments<R>, addr: VmAddr) -> Result<Self> {
        const HEADER_SIZE: usize = size_of::<ElfGnuHeader>();
        let start = addr
            .checked_offset_from(segments.base())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let mut bytes = [0u8; HEADER_SIZE];
        segments.read_bytes(addr, &mut bytes)?;
        let header: ElfGnuHeader = unsafe { core::mem::transmute(bytes) };

        if header.nbloom == 0 {
            return Err(ParseDynamicError::MalformedHashTable {
                detail: "DT_GNU_HASH bloom filter is empty",
            }
            .into());
        }

        if header.nbucket == 0 {
            return Err(ParseDynamicError::MalformedHashTable {
                detail: "DT_GNU_HASH bucket table is empty",
            }
            .into());
        }

        let bloom_size = (header.nbloom as usize)
            .checked_mul(size_of::<L::Word>())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let bucket_size = (header.nbucket as usize)
            .checked_mul(size_of::<u32>())
            .ok_or(ParseDynamicError::AddressOverflow)?;

        let blooms_off = start
            .checked_add(HEADER_SIZE)
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let buckets_off = blooms_off
            .checked_add(bloom_size)
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let chains_off = buckets_off
            .checked_add(bucket_size)
            .ok_or(ParseDynamicError::AddressOverflow)?;

        let blooms = segments.read_view(blooms_off, bloom_size).ok_or(
            ParseDynamicError::MalformedHashTable {
                detail: "DT_GNU_HASH bloom filter size is malformed",
            },
        )?;
        let buckets = segments.read_view(buckets_off, bucket_size).ok_or(
            ParseDynamicError::MalformedHashTable {
                detail: "DT_GNU_HASH bucket table size is malformed",
            },
        )?;
        let chain_count = Self::count_chain_entries(segments, chains_off, &header, &buckets)?;
        let chain_size = chain_count
            .checked_mul(size_of::<u32>())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let chains = segments.read_view(chains_off, chain_size).ok_or(
            ParseDynamicError::MalformedHashTable {
                detail: "DT_GNU_HASH chain table size is malformed",
            },
        )?;

        Ok(Self {
            header,
            blooms,
            buckets,
            chains,
        })
    }

    fn count_chain_entries<R: RegionAccess>(
        segments: &ElfSegments<R>,
        chains_off: VmOffset,
        header: &ElfGnuHeader,
        buckets: &MappedView<u32>,
    ) -> Result<usize> {
        let Some(nsym) = buckets
            .as_slice()
            .iter()
            .copied()
            .max()
            .map(|idx| idx as usize)
        else {
            return Ok(0);
        };

        if nsym == 0 {
            return Ok(0);
        }

        let symbias = header.symbias as usize;
        if nsym < symbias {
            return Err(ParseDynamicError::MalformedHashTable {
                detail: "DT_GNU_HASH bucket index precedes symbol bias",
            }
            .into());
        }

        let mut idx = nsym - symbias;
        loop {
            let offset = idx
                .checked_mul(size_of::<u32>())
                .ok_or(ParseDynamicError::AddressOverflow)?;
            let offset = chains_off
                .checked_add(offset)
                .ok_or(ParseDynamicError::AddressOverflow)?;
            let mut bytes = [0u8; size_of::<u32>()];
            segments.read_bytes(segments.base().wrapping_add(offset), &mut bytes)?;
            let value = u32::from_ne_bytes(bytes);
            if value & 1 != 0 {
                return Ok(idx
                    .checked_add(1)
                    .ok_or(ParseDynamicError::AddressOverflow)?);
            }
            idx = idx
                .checked_add(1)
                .ok_or(ParseDynamicError::AddressOverflow)?;
        }
    }
}

impl<Layout: ElfLayout> ElfHashTable for ElfGnuHash<Layout> {
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
        let buckets = self.buckets.as_slice();
        let chains = self.chains.as_slice();

        // Find the maximum symbol index referenced by buckets
        for bucket in buckets {
            nsym = nsym.max(*bucket as usize);
        }

        // If we found a valid symbol index, check the chains for the end marker
        if nsym > 0 {
            let mut idx = nsym.saturating_sub(self.header.symbias as usize);
            while chains.get(idx).is_some_and(|chain| chain & 1 == 0) {
                nsym += 1;
                idx += 1;
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
    fn lookup<'sym, L: ElfLayout>(
        table: &'sym SymbolTable<L>,
        symbol: &SymbolInfo,
        precompute: &mut PreCompute,
    ) -> Option<&'sym ElfSymbol<L>> {
        // Get precomputed hash values
        let hash = precompute.gnuhash;
        let word_bits = L::Word::BITS;
        let fofs = hash as usize / word_bits;
        let fmask = 1u64 << (hash as usize % word_bits);

        // Get the hash table implementation
        let hashtab = table.hashtab.into_gnuhash().unwrap();
        let blooms = hashtab.blooms.as_slice();
        let buckets = hashtab.buckets.as_slice();
        let chains = hashtab.chains.as_slice();

        // Check bloom filter for fast negative lookup
        let bloom_idx = fofs & (hashtab.header.nbloom - 1) as usize;
        let filter = blooms.get(bloom_idx)?.to_u64();

        // First bloom filter check
        if filter & fmask == 0 {
            return None;
        }

        // Second bloom filter check
        let filter2 = filter >> ((hash >> hashtab.header.nshift) as usize % word_bits);
        if filter2 & 1 == 0 {
            return None;
        }

        // Bloom filters passed, now check the actual hash chains
        let table_start_idx = hashtab.header.symbias as usize;
        let chain_start_idx =
            *buckets.get((hash as usize) % hashtab.header.nbucket as usize)? as usize;

        // If bucket is empty, symbol is not present
        if chain_start_idx == 0 {
            return None;
        }

        // Traverse the chain to find the symbol
        #[cfg(feature = "version")]
        let mut dynsym_idx = chain_start_idx;
        let mut chain_idx = chain_start_idx.checked_sub(table_start_idx)?;
        let mut cur_symbol_idx = chain_start_idx;

        loop {
            let chain_hash = *chains.get(chain_idx)?;

            // Check if this chain entry matches our hash (ignoring LSB)
            if hash | 1 == chain_hash | 1 {
                let cur_symbol = table.symbols.get(cur_symbol_idx)?;
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
            chain_idx += 1;
            cur_symbol_idx += 1;
            #[cfg(feature = "version")]
            {
                dynsym_idx += 1;
            }
        }

        // Symbol not found in the chain
        None
    }
}
