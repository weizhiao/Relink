use super::{layout::checked_add, writer::ByteWriter};
use crate::{Result, custom_error};
use alloc::vec::Vec;

/// Computes the standard SYSV ELF hash for a symbol name.
pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;

    for byte in name {
        hash = (hash << 4).wrapping_add(u32::from(*byte));
        let g = hash & 0xf0000000;
        if g != 0 {
            hash ^= g >> 24;
        }
        hash &= !g;
    }

    hash
}

#[inline]
pub(super) fn dynsym_bucket_count(symbol_count: usize) -> usize {
    const PRIMES: &[usize] = &[
        1, 3, 7, 17, 37, 67, 131, 257, 521, 1031, 2053, 4099, 8209, 16411,
    ];
    let wanted = (symbol_count / 2).max(1);
    PRIMES
        .iter()
        .copied()
        .find(|prime| *prime >= wanted)
        .unwrap_or(wanted)
}

#[inline]
pub(super) fn sysv_hash_table_size(symbol_count: usize, bucket_count: usize) -> Result<usize> {
    checked_add(
        2usize,
        checked_add(
            bucket_count,
            symbol_count,
            "generated DSO hash table overflow",
        )?,
        "generated DSO hash table overflow",
    )
    .and_then(|words| {
        words
            .checked_mul(4)
            .ok_or_else(|| custom_error("generated DSO hash table overflow"))
    })
}

pub(super) fn write_sysv_hash_table<'a>(
    dest: &mut [u8],
    symbol_count: usize,
    bucket_count: usize,
    names: impl IntoIterator<Item = &'a str>,
) {
    let mut buckets = Vec::new();
    buckets.resize(bucket_count, 0u32);
    let mut chains = Vec::new();
    chains.resize(symbol_count, 0u32);

    for (idx, name) in names.into_iter().enumerate() {
        let sym_idx = idx + 1;
        let bucket = (sysv_hash(name.as_bytes()) as usize) % bucket_count;
        chains[sym_idx] = buckets[bucket];
        buckets[bucket] = sym_idx as u32;
    }

    let mut out = ByteWriter::new(dest);
    out.u32(bucket_count as u32);
    out.u32(symbol_count as u32);
    for bucket in buckets {
        out.u32(bucket);
    }
    for chain in chains {
        out.u32(chain);
    }
}
