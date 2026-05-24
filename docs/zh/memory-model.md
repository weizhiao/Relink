# Relink 内存模型

`src/os/memory` 是 Relink 里“已经映射好的内存该怎么被访问”的抽象层。

它不负责决定 ELF 段应该映射到哪里，也不直接实现 Linux `mmap`、Windows `VirtualAlloc` 这些系统调用。那些事情在 `src/os/traits.rs` 的 `Mmap` 后端和各个平台实现里完成。`src/os/memory` 更像是映射完成后的统一访问接口：给定一块内存，loader、relocator、symbol table parser 应该用同一套方式读、写、借用和改权限。

下图展示了这套模型里几个核心类型的职责和调用关系：

![Relink 内存模型的核心交互](../assets/memory-model.png)

## 为什么需要这一层

ELF loader 看起来是在处理文件格式，但真正麻烦的是“这些字节现在在哪”。

同一份 ELF 数据可能来自几种地方：

- 文件映射：直接把文件页映射进进程地址空间。
- 内存输入：用户传进来的 `&[u8]`，loader 需要复制到自己的映射空间。
- 预先存在的映射：动态链接器启动时，主程序可能已经被内核映射好了。
- 自定义运行时：内核、嵌入式或 guest VM 可能没有普通的 host mmap。

如果每个模块都直接拿裸指针和 `usize` 算地址，代码会很快变得脆弱。`src/os/memory` 的目标就是把这些差异收在一个地方，让上层只关心：

- 这块区域的运行时地址是多少？
- 我能不能从某个 offset 读一段 bytes？
- 我能不能得到一个 host pointer 来复制数据？
- 这段内存最后由谁释放？

## 核心类型

### `VmAddr` 和 `VmOffset`

`VmAddr` 表示运行时虚拟地址，`VmOffset` 表示 ELF 镜像内部的虚拟偏移。

这两个类型都是 `usize` 的轻量包装，但语义不同：

```text
VmAddr   = 进程/运行时里的地址，例如 0x7f00_1234_0000
VmOffset = 镜像内部的偏移，例如 p_vaddr、section offset、symbol value
```

常见关系是：

```text
runtime address = load base + vm offset
```

所以代码里会写成：

```rust,ignore
let addr = base + offset;
```

这样比到处传 `usize` 更不容易把“地址”和“偏移”混在一起。需要回到普通数值时再显式 `.get()`。

### `RegionAccess`

`RegionAccess` 是真正的访问能力接口。它描述“某块内存区域可以怎样被访问”。

主要方法有：

- `addr()`：区域起始虚拟地址。
- `len()`：区域长度。
- `read_bytes()` / `write_bytes()`：读写字节。
- `read_value()` / `write_value()`：读写一个 typed value。
- `zero_bytes()`：清零一段范围。
- `borrow_bytes()`：直接借出 host 可读 slice。
- `host_ptr()`：拿到 host pointer，用于高效 copy。
- `madvise()` / `mprotect()`：把操作转发给底层 mmap 后端。

这些方法多数是 `unsafe`，原因不是接口本身会随意越界，而是它们默认调用方已经做过范围检查。这样热路径不需要每一层重复检查边界。

换句话说：

```text
ElfSegments 负责判断“这个地址在不在映射范围里”
RegionAccess 负责执行“对这个 offset 做读写”
```

### `MappedRegion`

`MappedRegion<R>` 是对一块已映射内存的共享句柄。

它内部用 `Arc<R>` 持有一个实现了 `RegionAccess` 的后端，所以 `MappedRegion` 可以廉价 clone。上层对象只需要保存 `MappedRegion`，不用关心底层到底是 host mmap、借用外部内存，还是未来某个 guest memory backend。

它提供了一组薄封装：

```rust,ignore
region.read_bytes(offset, dst)
region.write_value(offset, value)
region.borrow_bytes(offset, len)
region.mprotect(offset, len, prot)
```

`MappedRegion` 不负责做复杂地址换算。它只知道自己的 region offset。更高层的 `ElfSegments` 会把 ELF runtime address 转换成 region offset。

### `HostRegion`

`HostRegion` 是最常见的 `RegionAccess` 实现：它背后是一段 host 进程可以直接访问的内存。

它保存四个字段：

```rust,ignore
host_ptr: *mut c_void,
len: usize,
control: M,
unmap_on_drop: bool,
```

其中 `control` 是 mmap 后端，用来处理 `mprotect`、`madvise`、`munmap` 这类平台操作。

最重要的是 `unmap_on_drop`。这决定了这块内存的生命周期是谁负责：

- `MappedRegion::local(...)`：这个 region 拥有内存，drop 时会调用 `munmap`。
- `MappedRegion::local_alias(...)`：这个 region 只是借用/别名，drop 时不会释放内存。

这两个名字很关键。比如 loader 自己通过 `create_space` 创建的整块空间应该是 `local`，因为它拥有生命周期。已经由内核或其他对象管理的内存则应该用 `local_alias`，避免错误释放。

### `MappedView`

`MappedView<T>` 是一个 typed borrowed view，内部就是一个 `&'static [T]`。

它常用于解析 ELF 表，比如 dynamic table、program header、symbol table。流程通常是：

```text
MappedRegion::borrow_bytes(...)
        |
        v
检查长度和对齐
        |
        v
MappedView<T>
```

它的好处是解析器拿到的是 `&[T]`，不用一直手动处理裸指针。但它只在底层内存确实可以被 host 直接借用时可用。如果后端不能直接暴露 host slice，就可以让 `borrow_bytes()` 返回 `None`，上层再走 copy/解析路径。

## 和 `ElfSegments` 的关系

`src/os/memory` 只描述“一块 region 怎么访问”。ELF 镜像通常还需要另一个信息：这块 region 对应哪些 runtime 地址范围。

这就是 `ElfSegments` 的职责。

简单说：

```text
MappedRegion:
    我有一块连续 backing memory。

ElfSegments:
    这块 backing memory 在 ELF runtime 地址空间里覆盖哪些范围。
```

`ElfSegments` 会保存：

- `base: VmAddr`：加载基址。
- `region: MappedRegion`：背后的实际内存。
- `ranges`：这个镜像实际映射的 runtime range。

当上层要读某个 runtime address 时，流程是：

```text
runtime address
    |
    v
ElfSegments 检查它是否落在 mapped ranges 内
    |
    v
转换成 region offset
    |
    v
MappedRegion / RegionAccess 执行读写
```

这样设计后，loader 可以支持不连续的 ELF 映射范围，同时底层仍然可以用一块共享 backing region 来承载。

## `Mmap` 后端和 memory 层怎么配合

`Mmap` 后端负责创建和填充地址空间。当前加载流程大致是：

```text
1. create_space(...)
   创建一整块拥有生命周期的 MappedRegion。

2. map_file_at(...)
   如果输入来自文件，并且可以直接映射，就把文件页映射到 space 的子范围。

3. copy bytes
   如果输入来自内存，或者 relocatable object 需要后续改写，就直接复制到 space。

4. map_zero_at(...)
   对需要独立零页的 BSS 尾部做匿名映射或提交。

5. mprotect(...)
   relocation 完成后，把段权限改成最终权限。
```

注意：copy path 不需要额外的 `map_copy_at`。它依赖 `create_space(..., populate_later = false)` 返回一块可写、host-accessible 的空间，然后 loader 直接把 bytes 复制进去。这样内存加载路径更短，也避免每个 segment 多一次系统调用。

## unsafe 边界

这一层有不少 `unsafe`，但它们各自承担的风险不同：

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

- `create_space(..., populate_later = false)` 返回可写、host-accessible 的空间。
- `create_space(..., populate_later = true)` 可以先保留地址空间，之后由 `map_file_at` / `map_zero_at` 填充。
- `munmap` 只释放由 `local` 拥有的空间。
- `map_file_at` 和 `map_zero_at` 不需要返回 region，它们填的是已有 space。

第二种是实现 `RegionAccess`。这适合更特殊的环境，比如 guest VM memory、内核内存对象，或者不能直接暴露 host pointer 的 backend。

实现 `RegionAccess` 时，重点是让这些能力符合实际情况：

- 能直接借出 host bytes，就实现 `borrow_bytes`。
- 能直接拿到 host pointer，就实现 `host_ptr`。
- 不能直接暴露，就返回 `None`，让上层选择别的路径。

## 小结

`src/os/memory` 的设计核心是把“内存在哪里”和“怎么访问它”分开：

- `Mmap`：负责创建和填充地址空间。
- `MappedRegion`：负责保存一块已映射区域的共享句柄。
- `RegionAccess`：负责对这块区域执行读写、清零、借用和权限操作。
- `HostRegion`：普通 host mmap 的具体实现。
- `VmAddr` / `VmOffset`：让地址和偏移的语义在类型上分开。
- `ElfSegments`：把 ELF runtime 地址映射到 `MappedRegion` 的 region offset。

这样上层 loader 可以用统一方式处理文件映射、内存加载、预映射镜像和自定义 runtime，而不用把平台细节散落在 ELF 解析和重定位代码里。
