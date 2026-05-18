use core::mem::size_of;

use crate::{ByteRepr, Result, os::VmAddr};

use super::MappedRegion;

/// A typed borrowed view of a mapped region.
pub(crate) struct MappedView<T: 'static> {
    source_addr: VmAddr,
    slice: &'static [T],
}

impl<T: 'static> Clone for MappedView<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            source_addr: self.source_addr,
            slice: self.slice,
        }
    }
}

impl<T: 'static> MappedView<T> {
    #[inline]
    pub(crate) const fn empty() -> Self {
        Self {
            source_addr: VmAddr::new(0),
            slice: &[],
        }
    }

    pub(crate) fn read_region(
        region: &MappedRegion,
        offset: usize,
        source_addr: VmAddr,
        byte_len: usize,
    ) -> Result<Option<Self>>
    where
        T: ByteRepr,
    {
        let elem_size = size_of::<T>();
        if elem_size == 0 || !byte_len.is_multiple_of(elem_size) {
            return Ok(None);
        }

        if byte_len == 0 {
            return Ok(Some(Self {
                source_addr,
                slice: &[],
            }));
        }

        let Some(bytes) = (unsafe { region.borrow_bytes(offset, byte_len) }) else {
            return Ok(None);
        };
        let (prefix, values, suffix) = unsafe { bytes.align_to::<T>() };
        if !prefix.is_empty() || !suffix.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            source_addr,
            slice: values,
        }))
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &'static [T] {
        self.slice
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.as_slice().len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    #[inline]
    pub(crate) fn source_end(&self) -> Option<VmAddr> {
        let byte_len = self.len().checked_mul(size_of::<T>())?;
        self.source_addr.checked_add(byte_len)
    }
}

impl<T: 'static> AsRef<[T]> for MappedView<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}
