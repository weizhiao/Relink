use core::{
    alloc::Layout,
    ffi::c_void,
    mem::{MaybeUninit, align_of, size_of},
    ptr::{self, NonNull},
};

use alloc::{alloc::dealloc, boxed::Box};

use crate::{
    ByteRepr, Result,
    os::{MadviseAdvice, Mmap, ProtFlags},
};

use super::{MappedRegion, RegionAccess, VmAddr};

enum Owner {
    Mapping { addr: VmAddr, len: usize },
    Allocation { ptr: NonNull<u8>, layout: Layout },
}

/// Host-addressable mmap region.
pub struct HostRegion {
    host_ptr: *mut c_void,
    len: usize,
    control: Option<Box<dyn Mmap<Region = HostRegion>>>,
    owner: Option<Owner>,
}

impl MappedRegion<HostRegion> {
    /// Exposes a host-backed range and unmaps the original mapping on drop.
    ///
    /// # Safety
    /// `allocation_ptr..allocation_ptr + allocation_len` must describe a valid,
    /// non-overflowing mapping or reservation owned by the caller. Ownership is
    /// transferred to the returned region: no other owner may release it, and
    /// it must remain valid until the last clone is dropped. The visible range
    /// `host_ptr..host_ptr + len` must lie within this mapping. `control` must
    /// support operations on the visible range and correctly release the original
    /// mapping through `munmap(allocation_ptr, allocation_len)`. Reserved pages
    /// must be populated with suitable permissions before access.
    #[inline]
    pub unsafe fn local<M>(
        host_ptr: *mut c_void,
        len: usize,
        allocation_ptr: *mut c_void,
        allocation_len: usize,
        control: M,
    ) -> Self
    where
        M: Mmap<Region = HostRegion>,
    {
        debug_assert!(
            (host_ptr as usize)
                .checked_sub(allocation_ptr as usize)
                .and_then(|offset| offset.checked_add(len))
                .is_some_and(|end| end <= allocation_len)
        );
        Self::new(HostRegion {
            host_ptr,
            len,
            control: Some(Box::new(control)),
            owner: Some(Owner::Mapping {
                addr: VmAddr::from_ptr(allocation_ptr),
                len: allocation_len,
            }),
        })
    }

    /// Owns a global allocation with its original layout and exposes a subrange.
    ///
    /// # Safety
    /// `ptr` must come from the global allocator using `layout`, and ownership
    /// must be transferred here. `offset..offset + len` must lie inside it.
    #[inline]
    pub(crate) unsafe fn local_allocated(
        ptr: NonNull<u8>,
        layout: Layout,
        offset: usize,
        len: usize,
    ) -> Self {
        debug_assert!(
            offset
                .checked_add(len)
                .is_some_and(|end| end <= layout.size())
        );
        Self::new(HostRegion {
            host_ptr: unsafe { ptr.as_ptr().add(offset).cast() },
            len,
            control: None,
            owner: Some(Owner::Allocation { ptr, layout }),
        })
    }

    /// Creates a host-backed mapped region alias that does not unmap on drop.
    ///
    /// # Safety
    /// `host_ptr..host_ptr + len` must describe a valid, non-overflowing mapping
    /// or address reservation. Its owner must keep it valid for the lifetime of
    /// every clone of the returned region. `control` must support operations on
    /// this range. The caller must coordinate accesses and protection changes
    /// with the owner and other aliases; pages need suitable permissions before access.
    #[inline]
    pub unsafe fn local_alias<M>(host_ptr: *mut c_void, len: usize, control: M) -> Self
    where
        M: Mmap<Region = HostRegion>,
    {
        Self::new(HostRegion {
            host_ptr,
            len,
            control: Some(Box::new(control)),
            owner: None,
        })
    }

    /// Creates a host-backed alias without taking ownership of the mapping.
    ///
    /// # Safety
    /// `host_ptr..host_ptr + len` must remain mapped and accessible for the
    /// lifetime of every clone of the returned region. The range must not overflow,
    /// and accesses must be coordinated with the owner and other aliases as for
    /// [`Self::local_alias`].
    #[inline]
    pub unsafe fn local_alias_no_unmap(host_ptr: *mut c_void, len: usize) -> Self {
        Self::new(HostRegion {
            host_ptr,
            len,
            control: None,
            owner: None,
        })
    }
}

impl RegionAccess for HostRegion {
    #[inline]
    fn addr(&self) -> VmAddr {
        VmAddr::new(self.host_ptr as usize)
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        unsafe {
            ptr::copy_nonoverlapping(
                self.host_ptr.cast::<u8>().add(offset),
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
        Ok(())
    }

    #[inline]
    unsafe fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }
        unsafe {
            ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.host_ptr.cast::<u8>().add(offset),
                src.len(),
            );
        }
        Ok(())
    }

    #[inline]
    unsafe fn read_value<T: ByteRepr>(&self, offset: usize) -> Result<T> {
        if size_of::<T>() == 0 {
            return Ok(unsafe { MaybeUninit::<T>::zeroed().assume_init() });
        }
        let ptr = unsafe { self.host_ptr.cast::<u8>().add(offset).cast::<T>() };
        debug_assert!((ptr as usize).is_multiple_of(align_of::<T>()));
        Ok(unsafe { ptr::read(ptr) })
    }

    #[inline]
    unsafe fn write_value<T: ByteRepr>(&self, offset: usize, value: T) -> Result<()> {
        if size_of::<T>() == 0 {
            return Ok(());
        }
        let ptr = unsafe { self.host_ptr.cast::<u8>().add(offset).cast::<T>() };
        debug_assert!((ptr as usize).is_multiple_of(align_of::<T>()));
        unsafe {
            ptr::write(ptr, value);
        }
        Ok(())
    }

    #[inline]
    unsafe fn zero_bytes(&self, offset: usize, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        unsafe {
            ptr::write_bytes(self.host_ptr.cast::<u8>().add(offset), 0, len);
        }
        Ok(())
    }

    #[inline]
    unsafe fn borrow_bytes(&self, offset: usize, len: usize) -> Option<&'static [u8]> {
        if len == 0 {
            return Some(&[]);
        }
        Some(unsafe { core::slice::from_raw_parts(self.host_ptr.cast::<u8>().add(offset), len) })
    }

    #[inline]
    unsafe fn host_ptr(&self, offset: usize) -> Option<NonNull<u8>> {
        Some(unsafe { NonNull::new_unchecked(self.host_ptr.cast::<u8>().add(offset)) })
    }

    #[inline]
    unsafe fn madvise(&self, offset: usize, len: usize, behavior: MadviseAdvice) -> Result<()> {
        let Some(control) = &self.control else {
            return Ok(());
        };
        unsafe {
            control.madvise(
                VmAddr::from_ptr(self.host_ptr.cast::<u8>().add(offset)),
                len,
                behavior,
            )
        }
    }

    #[inline]
    unsafe fn mprotect(&self, offset: usize, len: usize, prot: ProtFlags) -> Result<()> {
        let Some(control) = &self.control else {
            return Ok(());
        };
        unsafe {
            control.mprotect(
                VmAddr::from_ptr(self.host_ptr.cast::<u8>().add(offset)),
                len,
                prot,
            )
        }
    }
}

impl Drop for HostRegion {
    fn drop(&mut self) {
        match &self.owner {
            Some(Owner::Mapping { addr, len }) => {
                let control = self
                    .control
                    .as_ref()
                    .expect("owned mapping must have a mapping backend");
                let _ = unsafe { control.munmap(*addr, *len) };
            }
            Some(Owner::Allocation { ptr, layout }) => unsafe { dealloc(ptr.as_ptr(), *layout) },
            None => {}
        }
    }
}

// Safety: mapped regions operate on an mmap-style allocation and delegate
// synchronization requirements to the mapping backend.
unsafe impl Send for HostRegion {}
// Safety: shared access only exposes byte operations over the mapped range.
unsafe impl Sync for HostRegion {}
