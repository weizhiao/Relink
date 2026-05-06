/// Round up a value to the nearest alignment boundary
///
/// # Arguments
/// * `x` - The value to round up
/// * `align` - The alignment boundary, which should be zero or a power of two
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

/// Round up a value to the nearest alignment boundary for any alignment.
///
/// Unlike [`roundup`], this helper does not assume `align` is a power of two.
/// Passing `0` leaves the value unchanged.
#[inline]
pub(crate) fn align_up(x: usize, align: usize) -> usize {
    let align = align.max(1);
    let remainder = x % align;
    if remainder == 0 {
        return x;
    }

    x.checked_add(align - remainder)
        .expect("alignment overflowed while rounding up value")
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
