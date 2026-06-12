use core::mem::{align_of, size_of};

use crate::{
    ByteRepr, IoError, MmapError, Result,
    elf::{ElfLayout, ElfShdr},
    memory::{ImageMemory, VmAddr},
};

#[inline]
pub(crate) fn section_bytes<L, Memory>(memory: &Memory, shdr: &ElfShdr<L>) -> Result<&'static [u8]>
where
    L: ElfLayout,
    Memory: ImageMemory + ?Sized,
{
    section_slice(memory, shdr, shdr.sh_size())
}

#[inline]
pub(crate) fn section_entries<L, T, Memory>(
    memory: &Memory,
    shdr: &ElfShdr<L>,
) -> Result<&'static [T]>
where
    L: ElfLayout,
    T: ByteRepr + 'static,
    Memory: ImageMemory + ?Sized,
{
    let byte_len = entry_bytes::<T>(shdr);
    section_slice(memory, shdr, byte_len)
}

#[inline]
pub(crate) fn section_entries_mut<L, T, Memory>(
    memory: &Memory,
    shdr: &ElfShdr<L>,
) -> Result<&'static mut [T]>
where
    L: ElfLayout,
    T: ByteRepr + 'static,
    Memory: ImageMemory + ?Sized,
{
    let byte_len = entry_bytes::<T>(shdr);
    let count = entry_count::<T>(byte_len);
    if count == 0 {
        return Ok(unsafe {
            core::slice::from_raw_parts_mut(core::ptr::NonNull::dangling().as_ptr(), 0)
        });
    }

    let ptr = section_ptr::<L, T, Memory>(memory, shdr, byte_len)?;
    Ok(unsafe { core::slice::from_raw_parts_mut(ptr, count) })
}

#[inline]
fn section_slice<L, T, Memory>(
    memory: &Memory,
    shdr: &ElfShdr<L>,
    byte_len: usize,
) -> Result<&'static [T]>
where
    L: ElfLayout,
    T: ByteRepr + 'static,
    Memory: ImageMemory + ?Sized,
{
    let count = entry_count::<T>(byte_len);
    if count == 0 {
        return Ok(&[]);
    }

    let ptr = section_ptr::<L, T, Memory>(memory, shdr, byte_len)?;
    Ok(unsafe { core::slice::from_raw_parts(ptr.cast_const(), count) })
}

#[inline]
fn section_ptr<L, T, Memory>(memory: &Memory, shdr: &ElfShdr<L>, byte_len: usize) -> Result<*mut T>
where
    L: ElfLayout,
    T: ByteRepr,
    Memory: ImageMemory + ?Sized,
{
    let ptr = memory
        .host_ptr_range(VmAddr::new(shdr.sh_addr()), byte_len)
        .ok_or(MmapError::HostPointerUnavailable)?;
    if !(ptr.as_ptr() as usize).is_multiple_of(align_of::<T>()) {
        return Err(IoError::ReadBufferNotAligned {
            align: align_of::<T>(),
        }
        .into());
    }
    Ok(ptr.as_ptr().cast())
}

#[inline]
fn entry_bytes<T>(shdr: &ElfShdr<impl ElfLayout>) -> usize {
    let entry_size = size_of::<T>();
    if entry_size == 0 {
        0
    } else {
        shdr.sh_size() / entry_size * entry_size
    }
}

#[inline]
fn entry_count<T>(byte_len: usize) -> usize {
    let entry_size = size_of::<T>();
    if entry_size == 0 {
        0
    } else {
        byte_len / entry_size
    }
}
