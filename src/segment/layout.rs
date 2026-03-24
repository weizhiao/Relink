/// Standard page size used for memory mapping operations
pub const PAGE_SIZE: usize = 0x1000;

/// Mask used to align addresses to page boundaries
pub const MASK: usize = !(PAGE_SIZE - 1);

/// Round up a value to the nearest alignment boundary
///
/// # Arguments
/// * `x` - The value to round up
/// * `align` - The alignment boundary
///
/// # Returns
/// The rounded up value
#[inline]
pub(crate) fn roundup(x: usize, align: usize) -> usize {
    if align == 0 {
        return x;
    }
    (x + align - 1) & !(align - 1)
}

/// Round down a value to the nearest alignment boundary
///
/// # Arguments
/// * `x` - The value to round down
/// * `align` - The alignment boundary
///
/// # Returns
/// The rounded down value
#[inline]
pub(crate) fn rounddown(x: usize, align: usize) -> usize {
    x & !(align - 1)
}
