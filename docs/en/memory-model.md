# Relink Memory Model

`src/os/memory` is the abstraction layer for accessing memory after it has already been mapped.

It does not decide where ELF segments should be placed, and it does not directly implement Linux `mmap` or Windows `VirtualAlloc`. Those jobs belong to the `Mmap` backend in `src/os/traits.rs` and the platform-specific implementations. `src/os/memory` is the common access layer after mapping: given a memory region, the loader, relocator, and table parsers should all read, write, borrow, and protect it through the same model.

You can think of it as three layers:

```text
platform mmap backend
    creates/populates virtual address space
        |
        v
MappedRegion
    stores a mapped region and manages its lifetime
        |
        v
RegionAccess
    reads, writes, zeroes, borrows, and protects that region
```

## Why This Layer Exists

An ELF loader looks like a file-format parser, but the hard part is often answering: where are these bytes now?

The same ELF data may come from several places:

- File mapping: file pages are mapped directly into the process address space.
- Memory input: the user passes `&[u8]`, and the loader copies bytes into its own mapped space.
- Existing mappings: during dynamic-linker startup, the kernel may have already mapped the main executable.
- Custom runtimes: kernels, embedded systems, or guest VMs may not have normal host mmap.

If every module handled raw pointers and `usize` arithmetic directly, the code would become fragile quickly. `src/os/memory` keeps those differences in one place, so upper layers only need to ask:

- What runtime address does this region start at?
- Can I read bytes from this offset?
- Can I get a host pointer for fast copying?
- Who releases this memory in the end?

## Core Types

### `VmAddr` And `VmOffset`

`VmAddr` represents a runtime virtual address. `VmOffset` represents an offset inside an ELF image's virtual address space.

Both are lightweight wrappers around `usize`, but they mean different things:

```text
VmAddr   = address in the process/runtime, such as 0x7f00_1234_0000
VmOffset = image-relative offset, such as p_vaddr, section offset, or symbol value
```

The common relationship is:

```text
runtime address = load base + vm offset
```

In code, that becomes:

```rust,ignore
let addr = base + offset;
```

This is harder to mix up than passing raw `usize` everywhere. When plain numeric values are needed, callers use `.get()` explicitly.

### `RegionAccess`

`RegionAccess` is the actual memory access interface. It describes what can be done with one mapped region.

The main methods are:

- `addr()`: base virtual address of the region.
- `len()`: region length.
- `read_bytes()` / `write_bytes()`: byte reads and writes.
- `read_value()` / `write_value()`: typed value reads and writes.
- `zero_bytes()`: zero a byte range.
- `borrow_bytes()`: borrow directly readable host bytes.
- `host_ptr()`: get a host pointer for fast copying.
- `madvise()` / `mprotect()`: forward advice/protection changes to the mmap backend.

Most access methods are `unsafe`. Not because the interface randomly goes out of bounds, but because callers are expected to have already checked the range. That keeps hot paths from repeating the same bounds checks at every layer.

In other words:

```text
ElfSegments checks whether an address is inside the mapped ranges.
RegionAccess performs the offset-based read or write.
```

### `MappedRegion`

`MappedRegion<R>` is a shared handle to a mapped region.

Internally it stores an `Arc<R>` where `R` implements `RegionAccess`, so cloning a `MappedRegion` is cheap. Upper layers can keep a `MappedRegion` without caring whether the backend is host mmap, borrowed external memory, or a future guest-memory adapter.

It provides thin wrappers such as:

```rust,ignore
region.read_bytes(offset, dst)
region.write_value(offset, value)
region.borrow_bytes(offset, len)
region.mprotect(offset, len, prot)
```

`MappedRegion` does not do complex ELF address translation. It only understands offsets inside its backing region. Higher layers such as `ElfSegments` translate ELF runtime addresses into region offsets.

### `HostRegion`

`HostRegion` is the common `RegionAccess` implementation for memory that the host process can access directly.

It stores four fields:

```rust,ignore
host_ptr: *mut c_void,
len: usize,
control: M,
unmap_on_drop: bool,
```

`control` is the mmap backend used for platform operations such as `mprotect`, `madvise`, and `munmap`.

The key field is `unmap_on_drop`. It decides who owns the memory lifetime:

- `MappedRegion::local(...)`: this region owns the memory and calls `munmap` on drop.
- `MappedRegion::local_alias(...)`: this region is only a borrowed alias and does not release memory on drop.

That distinction matters. A region created by the loader through `create_space` should usually be `local`, because it owns the mapping. Memory already managed by the kernel or another object should use `local_alias` to avoid freeing memory it does not own.

### `MappedView`

`MappedView<T>` is a typed borrowed view. Internally, it is just a `&'static [T]`.

It is used for parsing ELF tables such as the dynamic table, program headers, and symbol tables. The usual flow is:

```text
MappedRegion::borrow_bytes(...)
        |
        v
check length and alignment
        |
        v
MappedView<T>
```

The parser then receives `&[T]` instead of manually handling raw pointers everywhere. This only works when the backend can expose directly readable host bytes. If it cannot, `borrow_bytes()` can return `None`, and upper layers can choose a copy/parse path instead.

## Relationship With `ElfSegments`

`src/os/memory` describes how to access one region. An ELF image also needs to know which runtime address ranges that region covers.

That is the job of `ElfSegments`.

In short:

```text
MappedRegion:
    I have one contiguous backing memory region.

ElfSegments:
    This backing memory covers these ranges in the ELF runtime address space.
```

`ElfSegments` stores:

- `base: VmAddr`: the load base.
- `region: MappedRegion`: the backing memory.
- `ranges`: the runtime ranges actually mapped by this image.

When an upper layer reads a runtime address, the flow is:

```text
runtime address
    |
    v
ElfSegments checks whether it is inside mapped ranges
    |
    v
convert it into a region offset
    |
    v
MappedRegion / RegionAccess performs the access
```

This lets the loader support sparse ELF runtime ranges while still using one shared backing region underneath.

## How `Mmap` And The Memory Layer Work Together

The `Mmap` backend creates and populates virtual address space. The loading flow is roughly:

```text
1. create_space(...)
   Create one owning MappedRegion.

2. map_file_at(...)
   If input comes from a file and can be mapped directly, map file pages into a subrange of the space.

3. copy bytes
   If input comes from memory, or if a relocatable object must be rewritten later, copy bytes directly into the space.

4. map_zero_at(...)
   Map or commit anonymous zero pages for BSS tails that need separate pages.

5. mprotect(...)
   After relocation, switch segments to their final protections.
```

The copy path does not need a separate `map_copy_at`. It relies on `create_space(..., populate_later = false)` returning writable, host-accessible memory. The loader then copies bytes into it directly. That keeps memory loading short and avoids one extra system call per segment.

## Unsafe Boundaries

This layer contains a fair amount of `unsafe`, but the risks are separated:

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

- `create_space(..., populate_later = false)` returns writable, host-accessible memory.
- `create_space(..., populate_later = true)` may reserve address space first, then let `map_file_at` / `map_zero_at` populate subranges.
- `munmap` only frees memory owned through `local`.
- `map_file_at` and `map_zero_at` do not return regions; they populate an existing space.

The second is implementing `RegionAccess`. This fits more specialized environments, such as guest VM memory, kernel memory objects, or backends that cannot expose a direct host pointer.

When implementing `RegionAccess`, expose only what is actually available:

- If host bytes can be borrowed directly, implement `borrow_bytes`.
- If a host pointer can be returned, implement `host_ptr`.
- If direct exposure is impossible, return `None` and let upper layers choose another path.

## Summary

The core idea of `src/os/memory` is to separate where memory is from how it is accessed:

- `Mmap`: creates and populates virtual address space.
- `MappedRegion`: stores a shared handle to a mapped region.
- `RegionAccess`: reads, writes, zeroes, borrows, and protects that region.
- `HostRegion`: implements the common host mmap case.
- `VmAddr` / `VmOffset`: keep address and offset semantics distinct.
- `ElfSegments`: maps ELF runtime addresses to `MappedRegion` offsets.

With this split, the loader can handle file mappings, memory inputs, pre-mapped images, and custom runtimes through one access model instead of spreading platform details through ELF parsing and relocation code.
