use super::{
    ObjectSections, ObjectSymbolTable,
    layout::{ObjectSegments, SectionSegments},
    section_entries,
};
use crate::{
    RelocationError, Result,
    elf::{ElfSectionType, ElfShdr, Lifecycle},
    input::PathBuf,
    memory::{HostRegion, RegionAccess, VmAddr},
    relocation::ObjectRelocationArch,
    runtime::CodeExecutor,
    sync::Arc,
    tls::{TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::boxed::Box;
use core::marker::PhantomData;

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<
    Tls,
    D = (),
    Arch: ObjectRelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) path: PathBuf,
    pub(crate) sections: ObjectSections<Arch::Layout>,
    pub(crate) symtab: ObjectSymbolTable<Arch::Layout>,
    pub(crate) init: Lifecycle,
    pub(crate) fini: Lifecycle,
    pub(crate) segments: ObjectSegments<R>,
    pub(crate) section_segments: SectionSegments<Arch>,
    pub(crate) tls_mod_id: Option<TlsModuleId>,
    pub(crate) tls_tp_offset: Option<TlsTpOffset>,
    pub(crate) user_data: D,
    pub(crate) executor: Arc<dyn CodeExecutor<Arch>>,
    _marker_tls: PhantomData<Tls>,
    _marker_arch: PhantomData<Arch>,
}

struct ObjectSectionData<Arch: ObjectRelocationArch> {
    symtab: ObjectSymbolTable<Arch::Layout>,
    init: Lifecycle,
    fini: Lifecycle,
}

impl<T, D, Arch, R> ObjectBuilder<T, D, Arch, R>
where
    T: TlsResolver<Arch>,
    Arch: ObjectRelocationArch,
    R: RegionAccess,
{
    fn prepare_lifecycle_array<Memory>(
        lifecycle_array_shdr: &ElfShdr<Arch::Layout>,
        memory: &Memory,
    ) -> Result<Lifecycle>
    where
        Memory: crate::memory::ImageMemory + ?Sized,
    {
        let array: &[usize] = section_entries(memory, lifecycle_array_shdr)?;
        let array = array.iter().copied().map(VmAddr::new).collect::<Box<[_]>>();
        Ok(Lifecycle::new(None, Some(array)))
    }

    fn prepare_section_data<Memory>(
        shdrs: &[ElfShdr<Arch::Layout>],
        memory: &Memory,
    ) -> Result<ObjectSectionData<Arch>>
    where
        Memory: crate::memory::ImageMemory + ?Sized,
    {
        let mut symtab = None;
        let mut init = Lifecycle::new(None, None);
        let mut fini = Lifecycle::new(None, None);

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => {
                    symtab = Some(ObjectSymbolTable::from_shdrs(shdr, shdrs, memory)?)
                }
                ElfSectionType::INIT_ARRAY => init = Self::prepare_lifecycle_array(shdr, memory)?,
                ElfSectionType::FINI_ARRAY => fini = Self::prepare_lifecycle_array(shdr, memory)?,
                _ => {}
            }
        }

        Ok(ObjectSectionData {
            symtab: symtab.ok_or(RelocationError::MissingSymbolTable)?,
            init,
            fini,
        })
    }

    pub(crate) fn new(
        path: PathBuf,
        sections: ObjectSections<Arch::Layout>,
        segments: ObjectSegments<R>,
        section_segments: SectionSegments<Arch>,
        user_data: D,
        executor: Arc<dyn CodeExecutor<Arch>>,
    ) -> Result<Self> {
        let shdrs = sections.headers();
        let ObjectSectionData { symtab, init, fini } = {
            let memory = segments.view();
            Self::prepare_section_data(shdrs, &memory)?
        };

        Ok(Self {
            path,
            sections,
            symtab,
            segments,
            section_segments,
            init,
            fini,
            tls_mod_id: None,
            tls_tp_offset: None,
            user_data,
            executor,
            _marker_tls: PhantomData,
            _marker_arch: PhantomData,
        })
    }
}
