//! GNU ELF hash table implementation
//!
//! This module implements the GNU hash table format used in modern ELF files.
//! The GNU hash table provides better performance and memory efficiency compared
//! to the traditional SYSV hash table.

use crate::{
    ParseDynamicError, Result,
    elf::{ElfLayout, ElfSymbol, ElfWord, SymbolLookup, SymbolTableView},
    memory::{ImageMemory, MappedView, RegionAccess, VmAddr, VmOffset},
    segment::ElfSegments,
};
use core::mem::size_of;

/// Header structure for GNU ELF hash tables
///
/// This structure represents the header of a GNU hash table, which contains
/// metadata about the hash table structure and layout.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ElfGnuHeader {
    /// Number of bucket entries in the hash table
    pub(crate) nbucket: u32,

    /// Symbol bias - index of the first symbol in the hash table
    pub(crate) symbias: u32,

    /// Number of bloom filter entries
    pub(crate) nbloom: u32,

    /// Shift count used in bloom filter operations
    pub(crate) nshift: u32,
}

// SAFETY: four native-endian u32 fields without padding.
unsafe impl crate::ByteRepr for ElfGnuHeader {}

impl ElfGnuHeader {
    #[inline]
    fn from_bytes(bytes: [u8; size_of::<Self>()]) -> Self {
        let [
            b0,
            b1,
            b2,
            b3,
            s0,
            s1,
            s2,
            s3,
            l0,
            l1,
            l2,
            l3,
            h0,
            h1,
            h2,
            h3,
        ] = bytes;
        Self {
            nbucket: u32::from_ne_bytes([b0, b1, b2, b3]),
            symbias: u32::from_ne_bytes([s0, s1, s2, s3]),
            nbloom: u32::from_ne_bytes([l0, l1, l2, l3]),
            nshift: u32::from_ne_bytes([h0, h1, h2, h3]),
        }
    }
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

impl<L: ElfLayout> Clone for ElfGnuHash<L> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            header: self.header,
            blooms: self.blooms.clone(),
            buckets: self.buckets.clone(),
            chains: self.chains.clone(),
        }
    }
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
        let header = ElfGnuHeader::from_bytes(bytes);

        if header.nbloom == 0 {
            return Err(ParseDynamicError::EmptyHashTable {
                table: "DT_GNU_HASH bloom filter",
            }
            .into());
        }

        if header.nbucket == 0 {
            return Err(ParseDynamicError::EmptyHashTable {
                table: "DT_GNU_HASH bucket table",
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

        let blooms = segments.read_view(blooms_off, bloom_size).ok_or_else(|| {
            ParseDynamicError::malformed_table(
                crate::elf::ElfDynamicTag::GNU_HASH,
                "bloom filter size is malformed",
            )
        })?;
        let buckets = segments
            .read_view(buckets_off, bucket_size)
            .ok_or_else(|| {
                ParseDynamicError::malformed_table(
                    crate::elf::ElfDynamicTag::GNU_HASH,
                    "bucket table size is malformed",
                )
            })?;
        let chain_count = Self::count_chain_entries(segments, chains_off, &header, &buckets)?;
        let chain_size = chain_count
            .checked_mul(size_of::<u32>())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let chains = segments.read_view(chains_off, chain_size).ok_or_else(|| {
            ParseDynamicError::malformed_table(
                crate::elf::ElfDynamicTag::GNU_HASH,
                "chain table size is malformed",
            )
        })?;

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
            return Err(ParseDynamicError::GnuHashBucketBeforeSymbolBias {
                bucket_symbol: nsym,
                symbol_bias: symbias,
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
            segments.read_bytes(segments.base() + offset, &mut bytes)?;
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

impl<L: ElfLayout> ElfGnuHash<L> {
    /// Reuses a relocation's own definition when no earlier chain candidate
    /// can win. Equal hashes fall back to ordinary name/version lookup.
    fn lookup_known_symbol<'sym>(
        &self,
        table: SymbolTableView<'sym, L>,
        lookup: &SymbolLookup<'_>,
    ) -> Option<&'sym ElfSymbol<L>> {
        let address = lookup.symbol_hint()?;
        let offset = address.checked_sub(table.symbols.as_ptr() as usize)?;
        let entry_size = size_of::<ElfSymbol<L>>();
        if entry_size == 0 || !offset.is_multiple_of(entry_size) {
            return None;
        }
        let symbol_index = offset / entry_size;
        let symbol = table.get_raw(symbol_index)?;
        if !symbol.is_exported() {
            return None;
        }
        #[cfg(feature = "version")]
        if !table.check_match(symbol_index, lookup.version()) {
            return None;
        }

        let chain_index = symbol_index.checked_sub(self.header.symbias as usize)?;
        let chains = self.chains.as_slice();
        let hash = *chains.get(chain_index)? | 1;
        // GNU hash chains follow symbol order. A terminal bit on the preceding
        // entry marks the start of this bucket. Any earlier same-name symbol
        // must have the same masked hash, including alternate symbol versions.
        let mut previous = chain_index;
        while previous != 0 {
            let chain_hash = chains[previous - 1];
            if chain_hash & 1 != 0 {
                break;
            }
            if chain_hash | 1 == hash {
                return None;
            }
            previous -= 1;
        }
        Some(symbol)
    }

    pub(crate) fn for_each(
        &self,
        table: SymbolTableView<'_, L>,
        visitor: &mut dyn FnMut(&ElfSymbol<L>),
    ) {
        let start = self.header.symbias as usize;
        let Some(end) = start.checked_add(self.chains.len()) else {
            return;
        };
        for index in start..end {
            let Some(symbol) = table.get_raw(index) else {
                break;
            };
            visitor(symbol);
        }
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
    pub(crate) fn lookup<'sym>(
        &self,
        table: SymbolTableView<'sym, L>,
        lookup: &mut SymbolLookup<'_>,
    ) -> Option<&'sym ElfSymbol<L>> {
        if let Some(symbol) = self.lookup_known_symbol(table, lookup) {
            return Some(symbol);
        }
        // Get precomputed hash values
        let hash = lookup.gnu_hash();
        let word_bits = L::Word::BITS;
        let fofs = hash as usize / word_bits;
        let fmask = 1u64 << (hash as usize % word_bits);

        let blooms = self.blooms.as_slice();
        let buckets = self.buckets.as_slice();
        let chains = self.chains.as_slice();

        // Check bloom filter for fast negative lookup
        let bloom_idx = fofs & (self.header.nbloom - 1) as usize;
        let filter = blooms.get(bloom_idx)?.to_u64();

        // First bloom filter check
        if filter & fmask == 0 {
            return None;
        }

        // Second bloom filter check
        let filter2 = filter >> ((hash >> self.header.nshift) as usize % word_bits);
        if filter2 & 1 == 0 {
            return None;
        }

        // Bloom filters passed, now check the actual hash chains
        let table_start_idx = self.header.symbias as usize;
        let chain_start_idx =
            *buckets.get((hash as usize) % self.header.nbucket as usize)? as usize;

        // If bucket is empty, symbol is not present
        if chain_start_idx == 0 {
            return None;
        }

        // Traverse the chain to find the symbol
        let mut chain_idx = chain_start_idx.checked_sub(table_start_idx)?;
        let mut cur_symbol_idx = chain_start_idx;

        loop {
            let chain_hash = *chains.get(chain_idx)?;

            // Check if this chain entry matches our hash (ignoring LSB)
            if hash | 1 == chain_hash | 1 {
                let cur_symbol = table.get_raw(cur_symbol_idx)?;
                let name_matches = table
                    .strtab
                    .matches_name(cur_symbol.st_name(), lookup.name());

                // Check if this is the symbol we're looking for
                #[cfg(feature = "version")]
                if name_matches && table.check_match(cur_symbol_idx, lookup.version()) {
                    return Some(cur_symbol);
                }
                #[cfg(not(feature = "version"))]
                if name_matches {
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
        }

        // Symbol not found in the chain
        None
    }
}
