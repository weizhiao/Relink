use crate::elf::{ElfStringTable, SymbolTable};
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use elf::abi;

/// The special GNU extension section .gnu.version_d has a section type of SHT_GNU_VERDEF
/// This section shall contain symbol version definitions. The number of entries
/// in this section shall be contained in the DT_VERDEFNUM entry of the Dynamic
/// Section .dynamic, and also the sh_info member of the section header.
/// The sh_link member of the section header shall point to the section that
/// contains the strings referenced by this section.
///
/// The .gnu.version_d section shall contain an array of VerDef structures
/// optionally followed by an array of VerDefAux structures.
#[repr(C)]
struct VerDef {
    /// Version revision. This field shall be set to 1.
    vd_version: u16,
    /// Version information flag bitmask.
    vd_flags: u16,
    /// VersionIndex value referencing the SHT_GNU_VERSYM section.
    vd_ndx: u16,
    /// Number of associated verdaux array entries.
    vd_cnt: u16,
    /// Version name hash value (ELF hash function).
    vd_hash: u32,
    /// Offset in bytes to a corresponding entry in an array of VerDefAux structures.
    vd_aux: u32,
    /// Offset to the next VerDef entry, in bytes.
    vd_next: u32,
}

impl VerDef {
    fn index(&self) -> usize {
        (self.vd_ndx & abi::VER_NDX_VERSION) as usize
    }
}

#[repr(C)]
struct VerDefAux {
    /// Offset to the version or dependency name string in the linked string table, in bytes.
    vda_name: u32,
    /// Offset to the next VerDefAux entry, in bytes.
    vda_next: u32,
}

/// The GNU extension section .gnu.version_r has a section type of SHT_GNU_VERNEED.
/// This section contains required symbol version definitions. The number of
/// entries in this section shall be contained in the DT_VERNEEDNUM entry of the
/// Dynamic Section .dynamic and also the sh_info member of the section header.
/// The sh_link member of the section header shall point to the referenced
/// string table section.
///
/// The section shall contain an array of VerNeed structures optionally
/// followed by an array of VerNeedAux structures.
#[repr(C)]
struct VerNeed {
    /// Version of structure. This value is currently set to 1,
    /// and will be reset if the versioning implementation is incompatibly altered.
    vn_version: u16,
    /// Number of associated verneed array entries.
    vn_cnt: u16,
    /// Offset to the file name string in the linked string table, in bytes.
    vn_file: u32,
    /// Offset to a corresponding entry in the VerNeedAux array, in bytes.
    vn_aux: u32,
    /// Offset to the next VerNeed entry, in bytes.
    vn_next: u32,
}

/// Version Need Auxiliary Entries from the .gnu.version_r section
#[repr(C)]
struct VerNeedAux {
    /// Dependency name hash value (ELF hash function).
    vna_hash: u32,
    /// Dependency information flag bitmask.
    vna_flags: u16,
    /// VersionIndex value used in the .gnu.version symbol version array.
    vna_other: u16,
    /// Offset to the dependency name string in the linked string table, in bytes.
    vna_name: u32,
    /// Offset to the next vernaux entry, in bytes.
    vna_next: u32,
}

impl VerNeedAux {
    fn index(&self) -> usize {
        (self.vna_other & abi::VER_NDX_VERSION) as usize
    }
}

struct VersionIndex(u16);

impl VersionIndex {
    fn index(&self) -> u16 {
        self.0 & abi::VER_NDX_VERSION
    }

    pub fn is_hidden(&self) -> bool {
        (self.0 & abi::VER_NDX_HIDDEN) != 0
    }
}

#[derive(Clone)]
struct VersionIndexTable {
    ptr: *const VersionIndex,
}

impl core::fmt::Debug for VersionIndexTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VersionIndexTable")
            .field("ptr", &self.ptr)
            .finish()
    }
}

impl VersionIndexTable {
    fn get(&self, sym_idx: usize) -> &VersionIndex {
        unsafe { &*self.ptr.add(sym_idx) }
    }
}

struct VerNeedAuxIterator {
    ptr: *const VerNeedAux,
    count: usize,
    num: usize,
}

impl Iterator for VerNeedAuxIterator {
    type Item = VerNeedAux;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count < self.num {
            let verneed_aux = unsafe { self.ptr.read() };
            self.ptr = unsafe { self.ptr.add(1) };
            self.count += 1;
            Some(verneed_aux)
        } else {
            None
        }
    }
}

#[derive(Clone)]
struct VerNeedTable {
    ptr: *const VerNeed,
    num: usize,
}

struct VerNeedIterator {
    ptr: *const VerNeed,
    count: usize,
    num: usize,
}

impl Iterator for VerNeedIterator {
    type Item = (VerNeed, VerNeedAuxIterator);

    fn next(&mut self) -> Option<Self::Item> {
        if self.count < self.num {
            let verneed = unsafe { self.ptr.read() };
            let verneed_aux = VerNeedAuxIterator {
                ptr: unsafe { self.ptr.byte_add(verneed.vn_aux as usize) } as *const VerNeedAux,
                count: 0,
                num: verneed.vn_cnt as usize,
            };
            self.ptr = unsafe { self.ptr.byte_add(verneed.vn_next as usize) };
            self.count += 1;
            Some((verneed, verneed_aux))
        } else {
            None
        }
    }
}

impl IntoIterator for &VerNeedTable {
    type IntoIter = VerNeedIterator;
    type Item = (VerNeed, VerNeedAuxIterator);

    fn into_iter(self) -> Self::IntoIter {
        VerNeedIterator {
            ptr: self.ptr,
            count: 0,
            num: self.num,
        }
    }
}

#[derive(Clone)]
struct VerDefTable {
    ptr: *const VerDef,
    num: usize,
}

struct VerDefIterator {
    ptr: *const VerDef,
    count: usize,
    num: usize,
}

struct VerDefAuxIterator {
    ptr: *const VerDefAux,
    count: usize,
    num: usize,
}

impl Iterator for VerDefAuxIterator {
    type Item = VerDefAux;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count < self.num {
            let verdef_aux = unsafe { self.ptr.read() };
            self.ptr = unsafe { self.ptr.add(1) };
            self.count += 1;
            Some(verdef_aux)
        } else {
            None
        }
    }
}

impl Iterator for VerDefIterator {
    type Item = (VerDef, VerDefAuxIterator);

    fn next(&mut self) -> Option<Self::Item> {
        if self.count < self.num {
            let verdef = unsafe { self.ptr.read() };
            let verdef_aux = VerDefAuxIterator {
                ptr: unsafe { self.ptr.byte_add(verdef.vd_aux as usize) } as *const VerDefAux,
                count: 0,
                num: verdef.vd_cnt as usize,
            };
            self.ptr = unsafe { self.ptr.byte_add(verdef.vd_next as usize) };
            self.count += 1;
            Some((verdef, verdef_aux))
        } else {
            None
        }
    }
}

impl IntoIterator for &VerDefTable {
    type IntoIter = VerDefIterator;
    type Item = (VerDef, VerDefAuxIterator);

    fn into_iter(self) -> Self::IntoIter {
        VerDefIterator {
            ptr: self.ptr,
            count: 0,
            num: self.num,
        }
    }
}

/// 保存着所有依赖的和定义的版本号
struct Version {
    name: &'static str,
    hash: u32,
}

impl core::fmt::Debug for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Version")
            .field("name", &self.name)
            .field("hash", &format_args!("0x{:x}", self.hash))
            .finish()
    }
}

pub(crate) struct ELFVersion {
    version_ids: VersionIndexTable,
    // 因为verdef和verneed的idx不重叠，因此我们可以使用数组将其存起来
    // 这样可以加快之后符号版本号的匹配
    versions: Vec<Version>,
}

impl core::fmt::Debug for ELFVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ELFVersion")
            .field("version_ids", &self.version_ids)
            .field("versions", &self.versions)
            .finish()
    }
}

impl ELFVersion {
    pub(crate) fn new(
        version_ids_off: Option<NonZeroUsize>,
        verneeds: Option<(NonZeroUsize, NonZeroUsize)>,
        verdefs: Option<(NonZeroUsize, NonZeroUsize)>,
        strtab: &ElfStringTable,
    ) -> Option<ELFVersion> {
        let version_ids_off = version_ids_off?;
        let mut versions = Vec::new();
        //记录最大的verison idx
        let mut ndx_max = 0;
        if let Some((ptr, num)) = verdefs {
            let verdef_table = VerDefTable {
                ptr: ptr.get() as _,
                num: num.get(),
            };
            for (verdef, _) in verdef_table.into_iter() {
                if ndx_max < verdef.index() {
                    ndx_max = verdef.index();
                }
            }
        }
        if let Some((ptr, num)) = verneeds {
            let verneed_table = VerNeedTable {
                ptr: ptr.get() as _,
                num: num.get(),
            };
            for (_, vna_iter) in verneed_table.into_iter() {
                for aux in vna_iter {
                    if ndx_max < aux.index() {
                        ndx_max = aux.index();
                    }
                }
            }
        }
        // 分配足够大的version数组
        versions.reserve(ndx_max + 1);
        unsafe { versions.set_len(ndx_max + 1) };
        if let Some((ptr, num)) = verdefs {
            let verdef_table = VerDefTable {
                ptr: ptr.get() as _,
                num: num.get(),
            };
            for (verdef, mut vd_iter) in verdef_table.into_iter() {
                let name = strtab.get_str(vd_iter.next().unwrap().vda_name as usize);
                versions[verdef.index()] = Version {
                    name,
                    hash: verdef.vd_hash,
                };
            }
        }
        if let Some((ptr, num)) = verneeds {
            let verneed_table = VerNeedTable {
                ptr: ptr.get() as _,
                num: num.get(),
            };
            for (_, vna_iter) in verneed_table.into_iter() {
                for aux in vna_iter {
                    let name = strtab.get_str(aux.vna_name as usize);
                    versions[aux.index()] = Version {
                        name,
                        hash: aux.vna_hash,
                    };
                }
            }
        }
        Some(ELFVersion {
            version_ids: VersionIndexTable {
                ptr: version_ids_off.get() as _,
            },
            versions,
        })
    }
}

pub(crate) struct SymbolVersion<'a> {
    name: &'a str,
    hash: u32,
    hidden: bool,
}

impl core::fmt::Debug for SymbolVersion<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SymbolVersion")
            .field("name", &self.name)
            .field("hash", &format_args!("0x{:x}", self.hash))
            .field("hidden", &self.hidden)
            .finish()
    }
}

impl<'a> SymbolVersion<'a> {
    /// glibc:_dl_elf_hash
    fn dl_elf_hash(name: &str) -> u32 {
        let bytes = name.as_bytes();
        let mut hash: u32 = u32::from(bytes[0]);

        if hash != 0 && bytes.len() > 1 {
            hash = (hash << 4) + u32::from(bytes[1]);
            if bytes.len() > 2 {
                hash = (hash << 4) + u32::from(bytes[2]);
                if bytes.len() > 3 {
                    hash = (hash << 4) + u32::from(bytes[3]);
                    if bytes.len() > 4 {
                        hash = (hash << 4) + u32::from(bytes[4]);
                        let mut name = &bytes[5..];
                        while let Some(&byte) = name.first() {
                            hash = (hash << 4) + u32::from(byte);
                            let hi = hash & 0xf0000000;
                            hash ^= hi >> 24;
                            name = &name[1..];
                        }
                        hash &= 0x0fffffff;
                    }
                }
            }
        }
        hash
    }

    pub(crate) fn new(name: &'a str) -> Self {
        let hash = Self::dl_elf_hash(name);
        SymbolVersion {
            name,
            hash,
            hidden: true,
        }
    }
}

impl SymbolTable {
    pub(crate) fn get_requirement(&self, sym_idx: usize) -> Option<SymbolVersion<'_>> {
        if let Some(gnu_version) = &self.version {
            let ver_ndx = gnu_version.version_ids.get(sym_idx);
            if ver_ndx.index() <= 1 {
                return None;
            }
            let hidden = ver_ndx.is_hidden();
            let version = &gnu_version.versions[ver_ndx.index() as usize];
            return Some(SymbolVersion {
                name: version.name,
                hash: version.hash,
                hidden,
            });
        }
        None
    }

    pub(crate) fn check_match(&self, sym_idx: usize, version: Option<&SymbolVersion>) -> bool {
        if let Some(version) = version {
            let gnu_version = self.version.as_ref().unwrap();
            let ver_ndx = gnu_version.version_ids.get(sym_idx);
            let def_hidden = ver_ndx.is_hidden();
            let def_version = &gnu_version.versions[ver_ndx.index() as usize];
            // 使用版本号一致的符号或者使用默认符号(这里认为第一个不隐藏的符号就是默认符号)
            if (def_version.hash == version.hash && def_version.name == version.name)
                || (!version.hidden && !def_hidden)
            {
                return true;
            }
            return false;
        }
        // 如果需要重定位的符号不使用重定位信息，那么我们始终返回第一个找到的符号
        true
    }
}
