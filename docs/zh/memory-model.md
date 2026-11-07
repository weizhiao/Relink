# Relink 内存模型

[`memory` 模块](../../src/memory/mod.rs) 提供已映射内存的访问接口。
[`Mmap` trait](../../src/os/traits.rs) 负责创建和填充映射，
`RegionAccess` 负责读写、借用以及权限和内存建议操作。

```text
Mmap                  创建和填充映射
  → MappedRegion      共享 RegionAccess 后端的所有权
    → ElfSegments     转换镜像地址，检查映射范围
      → ImageMemory   向加载器提供基于地址的访问接口
```

这套模型适用于文件映射、字节缓冲区复制、已映射的可执行文件和自定义地址空间。

## 地址与偏移

`VmAddr` 表示目标地址空间中的虚拟地址。`VmOffset` 表示镜像内的虚拟偏移，
例如程序头的 `p_vaddr`，不表示文件偏移。两者都包装 `usize`，通过 `.get()` 取出数值。

```rust
use elf_loader::memory::{VmAddr, VmOffset};

let base = VmAddr::new(0x400000);
let offset = VmOffset::new(0x1000);
let addr = base + offset;
assert_eq!(addr.get(), 0x401000);
```

加载基址用于重定位，满足 `运行时地址 = 加载基址 + 虚拟偏移`，不一定等于底层区域的起始地址。
只有后端提供宿主可访问的内存时，目标地址才能作为宿主指针使用。

## 区域与所有权

`RegionAccess` 描述一块连续内存区域，提供字节和类型化读写、清零、可选的宿主访问，
以及权限和内存建议操作。调用未检查边界的方法前，调用方必须验证范围。
借用切片时还必须保持映射有效，并防止同一范围在借用期间被修改。
后端返回错误的能力不能替代这些安全要求。

`MappedRegion<R>` 通过 `Arc<R>` 共享后端。克隆句柄会保留同一块区域，最后一个句柄释放时
才销毁后端。内部访问方法使用相对区域起点的偏移，而非 ELF 虚拟偏移。

`HostRegion` 用于访问当前进程中的内存：

- `MappedRegion::local` 持有映射，最后一个句柄释放时通过后端的 `munmap` 释放原始分配范围。
- `MappedRegion::local_alias` 借用映射。所有者必须保证映射仍然有效，并与所有别名协调访问和权限变更。
- `MappedRegion::local_alias_no_unmap` 借用内存，但不附带控制映射的后端。

`AllocMmap` 保存原始分配指针和 Rust `Layout`，销毁时调用 `dealloc`。
其裸 `munmap(addr, len)` 返回错误，因为仅凭地址和长度无法确定原始分配布局。

`MappedView<T>` 是内部使用的类型化借用视图。保存的 `'static` 切片不拥有映射；
持有视图的镜像仍须维持内存生命周期并遵守借用约束。构造视图前需要检查长度和对齐。
无法暴露宿主内存的后端可从 `borrow_bytes` 返回 `None`；调用方必须处理这种情况，
不能假定所有解析路径都能直接借用内存。

## 镜像地址转换

`ElfSegments` 保存加载基址、底层 `MappedRegion` 和相对镜像的 `MappedRange` 列表。
底层区域虽然连续，镜像的有效映射范围可以不连续。访问时先检查请求范围是否属于镜像，
再将地址换算为底层区域内的偏移。

`ImageMemory` 提供基于地址的范围查询、字节访问和可选的宿主指针。
`ImageMemoryExt` 提供类型化访问方法，使 `ImageMemory` 本身仍可作为 trait object 使用。

## `Mmap` 后端和 memory 层怎么配合

`Mmap` 后端负责创建和填充地址空间。当前加载流程大致是：

```text
1. create_space(layout, prot, init)
   按 SpaceLayout 和 SpaceInit::Reserve、Zeroed 或 File 创建一整块拥有生命周期的 MappedRegion。

2. map_file_at(...)
   如果输入来自文件，并且可以直接映射，就把文件页映射到 space 的子范围。

3. copy bytes
   如果输入来自内存，或者 relocatable object 需要后续改写，就直接复制到 space。

4. map_zero_at(...)
   对需要独立零页的 BSS 尾部做匿名映射或提交。

5. mprotect(...)
   relocation 完成后，把段权限改成最终权限。
```

注意：copy path 不需要额外的 `map_copy_at`。它用可写权限调用 `create_space(..., SpaceInit::Zeroed)`，然后直接把 bytes 复制到已清零、host-accessible 的空间中。这样内存加载路径更短，也避免每个 segment 多一次系统调用。`SpaceInit::File { fd, offset }` 则可以用私有文件映射初始化空间，权限由调用方的 `prot` 指定，不限定为只读。

`SpaceLayout { addr, len, align, offset }` 单独描述地址布局，与初始内容无关。`addr` 保留各后端原有的地址选择语义：原生后端将它作为地址提示，allocator 和 fixed 后端用它选择调用方提供的存储。后端返回长度为 `len` 的 region，其起始地址满足 `start % align == offset % align`。`len` 必须非零且为后端页大小的整数倍。`align` 必须是至少等于后端页大小的二次幂，`offset` 必须按页对齐。这里的 offset 用于地址对齐，文件位置则由 `SpaceInit::File` 单独指定。加载 program segments 时，loader 使用 `min_vaddr` 作为布局 offset，从而使加载基址 `image_start - min_vaddr` 满足 ELF 的对齐要求。超过一页的对齐由后端处理。

初始文件映射可以直接提供第一个 program segment 的内容。段页面连续且每个 `PT_LOAD` 都满足 `p_filesz > 0` 时，文件偏移与初始映射一致的后续段也会复用该映射，只原地调整权限；文件偏移不同的段仍重新映射。存在空洞或后续段文件范围为空时，后续段仍走公共填充流程。首段文件范围为空或段页面重叠时采用普通空间预留，保持原有映射顺序。段间空洞保持不可访问。

所有文件映射段共用 BSS 处理：文件末页会一直清零到页边界，包括段内存末尾之后供解释器自举分配器使用的填充空间；需要时临时增加写权限，完成后恢复原权限；完整的 BSS 页采用匿名零页映射。

## unsafe 边界

各层的 `unsafe` 操作有不同的约束：

- `Mmap` 后端的 `unsafe`：会改进程虚拟地址空间，调用错了可能破坏映射。
- `RegionAccess` 的 `unsafe`：默认调用方已经保证 offset 和 len 在 region 内。
- `HostRegion` 里的裸指针操作：把 offset 转成指针并读写 bytes/value。

边界划分的原则是：

```text
上层做语义检查和范围检查
底层只做具体访问操作
```

例如 `ElfSegments` 会先判断地址是否属于当前 ELF 镜像；只有确认合法后，才调用 `MappedRegion` 上的 unchecked 读写方法。

## 如果要接入自定义后端

如果你的环境不是普通 Linux/Windows mmap，通常有两种接入方式。

第一种是实现 `Mmap`。这适合你仍然能创建一块 host 可访问的内存，只是分配、映射、改权限的方式不同。

需要重点保证：

- 所有初始化方式都遵守 `SpaceLayout`，包括超过后端页大小的对齐和非零的对齐 offset。
- `create_space(..., SpaceInit::Zeroed)` 将整个范围清零并应用指定的 `prot`；copy path 会请求可写、host-accessible 的空间。
- `create_space(..., SpaceInit::Reserve)` 可以先保留地址空间，之后由 `map_file_at` / `map_zero_at` 填充，再访问内容。
- `create_space(..., SpaceInit::File { fd, offset })` 按指定的 `prot` 建立私有文件映射。不支持这种初始化方式的后端必须在没有副作用的情况下返回 `MmapError::FileMappingUnsupported`，loader 才能回退到 `Reserve`，再通过 `map_file_at` 填充各段。逐段文件映射与整块文件初始化是独立的能力；其他映射错误直接向上传递，不进行回退。
- `munmap` 只释放由 `local` 拥有的空间。
- `map_file_at` 和 `map_zero_at` 不需要返回 region，它们填的是已有 space。

第二种是实现 `RegionAccess`。这适合更特殊的环境，比如 guest VM memory、内核内存对象，或者不能直接暴露 host pointer 的 backend。

实现 `RegionAccess` 时，重点是让这些能力符合实际情况：

- 能直接借出 host bytes，就实现 `borrow_bytes`。
- 能直接拿到 host pointer，就实现 `host_ptr`。
- 不能直接暴露，就返回 `None`，让上层选择别的路径。
