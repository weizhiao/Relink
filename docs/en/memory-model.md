# Relink Memory Model

The [`memory` module](../../src/memory/mod.rs) provides access to mapped memory.
The [`Mmap` trait](../../src/os/traits.rs) creates and populates mappings;
`RegionAccess` reads, writes, borrows, and protects their contents.

```text
Mmap                  creates and populates a mapping
  → MappedRegion      shares ownership of a RegionAccess backend
    → ElfSegments     translates image addresses and checks mapped ranges
      → ImageMemory   exposes address-based access to the rest of the loader
```

This model covers file mappings, copied byte buffers, pre-mapped executables,
and custom address spaces.

## Addresses and Offsets

`VmAddr` is an address in the target address space. `VmOffset` is an image-relative
virtual offset, such as a program header's `p_vaddr`. Neither is a file offset.
Both wrap `usize`; `.get()` returns the numeric value.

```rust
use elf_loader::memory::{VmAddr, VmOffset};

let base = VmAddr::new(0x400000);
let offset = VmOffset::new(0x1000);
let addr = base + offset;
assert_eq!(addr.get(), 0x401000);
```

The load base is a relocation bias: `runtime address = load base + virtual offset`.
It may differ from the start of the backing region. A target address is only
usable as a host pointer when the backend exposes host-accessible memory.

## Regions and Ownership

`RegionAccess` describes one contiguous memory region. It provides byte and typed
reads/writes, zeroing, optional host access, and protection/advice operations.
Unchecked methods require the caller to validate the range. Borrowing also requires
keeping the mapping alive and preventing mutation while the slice is in use.
Backend errors do not replace these safety requirements.

`MappedRegion<R>` shares a backend through `Arc<R>`. Cloning retains the same region;
the backend is dropped when its last handle is dropped. Its internal access helpers
use region-relative offsets, not ELF virtual offsets.

`HostRegion` implements access to memory in the current process:

- `MappedRegion::local` owns a mapping and releases the original allocation through
  the backend's `munmap` when the last handle is dropped.
- `MappedRegion::local_alias` borrows a mapping. Its owner must keep the mapping
  alive and coordinate access and protection changes with all aliases.
- `MappedRegion::local_alias_no_unmap` borrows memory without a mapping-control backend.

`AllocMmap` retains the original allocation pointer and Rust `Layout`, then calls
`dealloc` on drop. Its raw `munmap(addr, len)` returns an error because the address
and length do not identify the allocation layout.

`MappedView<T>` is an internal typed view of borrowed bytes. Its stored `'static`
slice does not own the mapping: the enclosing image must retain the memory and
respect the borrow. Creating a view requires suitable length and alignment.
Backends that cannot expose host bytes return `None` from `borrow_bytes`; callers
must handle that case rather than assume every parsing path can borrow memory.

## Image Address Translation

`ElfSegments` retains a load base, a backing `MappedRegion`, and image-relative
`MappedRange` entries. The ranges can be sparse even though the backing region is
contiguous. Access first checks that the requested address range belongs to the
image, then converts it to an offset in the backing region.

`ImageMemory` exposes this address-based view through range queries, byte access,
and optional host pointers. `ImageMemoryExt` adds typed access helpers while
keeping `ImageMemory` usable as a trait object.

## How `Mmap` And The Memory Layer Work Together

The `Mmap` backend creates and populates virtual address space. The loading flow is roughly:

```text
1. create_space(layout, prot, init)
   Create one owning MappedRegion with a SpaceLayout and SpaceInit::Reserve, Zeroed, or File.

2. map_file_at(...)
   If input comes from a file and can be mapped directly, map file pages into a subrange of the space.

3. copy bytes
   If input comes from memory, or if a relocatable object must be rewritten later, copy bytes directly into the space.

4. map_zero_at(...)
   Map or commit anonymous zero pages for BSS tails that need separate pages.

5. mprotect(...)
   After relocation, switch segments to their final protections.
```

The copy path does not need a separate `map_copy_at`. It calls `create_space(..., SpaceInit::Zeroed)` with writable protection, then copies bytes directly into the zero-initialized, host-accessible memory. That keeps memory loading short and avoids one extra system call per segment. `SpaceInit::File { fd, offset }` can instead initialize the space with a private file mapping using the caller's `prot`; it does not impose read-only protection.

`SpaceLayout { addr, len, align, offset }` describes the address layout independently of the initial contents. `addr` preserves the backend's address selection behavior: native backends use it as a placement hint, while allocator and fixed backends use it to select caller-owned storage. The backend returns a region of `len` bytes whose starting address satisfies `start % align == offset % align`. `len` must be nonzero and a multiple of the backend page size. `align` must be a power of two at least as large as the backend page size, and `offset` must be page-aligned. This offset describes address alignment; the file position is specified separately by `SpaceInit::File`. For program segments, the loader uses `min_vaddr` as the layout offset, so the load base `image_start - min_vaddr` satisfies the ELF alignment. Alignments larger than one page are handled by the backend.

An initial file mapping can supply the first program segment. When segment pages are contiguous and every `PT_LOAD` has `p_filesz > 0`, later segments also reuse that mapping where their file offsets match, adjusting protection in place; segments with different file offsets are remapped. Gaps or later segments with empty file ranges keep later segments on the common population path. An empty file range in the first segment or overlapping segment pages selects ordinary space reservation, preserving the original mapping order. Gaps remain inaccessible.

All file-backed segments share BSS handling: zeroing covers the rest of the partial file page, including padding beyond the segment's memory end used by interpreter bootstrap allocators; it temporarily adds write permission when needed and restores the original protection. Complete BSS pages use anonymous zero mappings.

## Unsafe Boundaries

The unsafe operations have separate responsibilities:

- `Mmap` backend `unsafe`: changes the process virtual address space. Incorrect calls can break mappings.
- `RegionAccess` `unsafe`: assumes the caller has already proven that offset and length are inside the region.
- `HostRegion` raw pointer operations: turn offsets into pointers and read/write bytes or values.

The boundary rule is:

```text
upper layers do semantic and range checks
lower layers perform the actual access
```

For example, `ElfSegments` first checks that an address belongs to the current ELF image. Only after that does it call unchecked access methods on `MappedRegion`.

## Adding A Custom Backend

There are usually two ways to plug in a non-standard environment.

The first is implementing `Mmap`. This is the right fit when you can still create host-accessible memory, but allocation, mapping, or protection changes are platform-specific.

The important guarantees are:

- Every initialization mode honors `SpaceLayout`, including alignments larger than the backend page size and a nonzero alignment offset.
- `create_space(..., SpaceInit::Zeroed)` initializes the entire range to zero and applies the requested `prot`. The copy path requests writable, host-accessible memory.
- `create_space(..., SpaceInit::Reserve)` may reserve address space first, then let `map_file_at` / `map_zero_at` populate subranges before access.
- `create_space(..., SpaceInit::File { fd, offset })` creates a private file mapping with the requested `prot`. A backend that cannot perform this initialization must return `MmapError::FileMappingUnsupported` without side effects. The loader can then use `Reserve` and populate segments with `map_file_at`; support for this operation is independent of support for whole-space file initialization. Other mapping errors propagate without fallback.
- `munmap` only frees memory owned through `local`.
- `map_file_at` and `map_zero_at` do not return regions; they populate an existing space.

The second is implementing `RegionAccess`. This fits more specialized environments, such as guest VM memory, kernel memory objects, or backends that cannot expose a direct host pointer.

When implementing `RegionAccess`, expose only what is actually available:

- If host bytes can be borrowed directly, implement `borrow_bytes`.
- If a host pointer can be returned, implement `host_ptr`.
- If direct exposure is impossible, return `None` and let upper layers choose another path.
