use super::{
    ObjectSections, ObjectSymbolTable,
    layout::{ObjectSegmentView, ObjectSegments, PltGotSection, SectionSegments},
    section_entries,
};
use crate::{
    RelocationError, Result,
    elf::{ElfSectionType, ElfShdr, Lifecycle},
    input::PathBuf,
    memory::{HostRegion, RegionAccess, VmAddr},
    relocation::ObjectRelocationArch,
    tls::{TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<
    Tls,
    D = (),
    Arch: ObjectRelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) path: PathBuf,
    pub(crate) shdrs: Vec<ElfShdr<Arch::Layout>>,
    pub(crate) symtab: ObjectSymbolTable<Arch::Layout>,
    pub(crate) init: Lifecycle,
    pub(crate) segments: ObjectSegments<R>,
    pub(crate) mprotect: Box<dyn for<'segments> Fn(&ObjectSegmentView<'segments, R>) -> Result<()>>,
    pub(crate) pltgot: PltGotSection,
    pub(crate) tls_mod_id: Option<TlsModuleId>,
    pub(crate) tls_tp_offset: Option<TlsTpOffset>,
    pub(crate) user_data: D,
    _marker_tls: PhantomData<Tls>,
    _marker_arch: PhantomData<Arch>,
}

struct ObjectSectionData<Arch: ObjectRelocationArch> {
    symtab: ObjectSymbolTable<Arch::Layout>,
    init: Lifecycle,
}

impl<T, D, Arch, R> ObjectBuilder<T, D, Arch, R>
where
    T: TlsResolver,
    Arch: ObjectRelocationArch,
    R: RegionAccess,
{
    fn prepare_init_array<Memory>(
        init_array_shdr: &ElfShdr<Arch::Layout>,
        memory: &Memory,
    ) -> Result<Lifecycle>
    where
        Memory: crate::memory::ImageMemory + ?Sized,
    {
        let array: &[usize] = section_entries(memory, init_array_shdr)?;
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

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => {
                    symtab = Some(ObjectSymbolTable::from_shdrs(shdr, shdrs, memory)?)
                }
                ElfSectionType::INIT_ARRAY => init = Self::prepare_init_array(shdr, memory)?,
                _ => {}
            }
        }

        Ok(ObjectSectionData {
            symtab: symtab.ok_or(RelocationError::MissingSymbolTable)?,
            init,
        })
    }

    pub(crate) fn new(
        path: PathBuf,
        mut sections: ObjectSections<Arch::Layout>,
        segments: ObjectSegments<R>,
        mut shdr_segments: SectionSegments<Arch>,
        user_data: D,
    ) -> Result<Self> {
        let shdrs = sections.headers_mut();
        let pltgot = shdr_segments.take_pltgot();
        let ObjectSectionData { symtab, init } = {
            let memory = segments.view();
            Self::prepare_section_data(shdrs, &memory)?
        };
        let mprotect =
            Box::new(move |segments: &ObjectSegmentView<'_, R>| shdr_segments.mprotect(segments));
        let shdrs = sections.into_headers();

        Ok(Self {
            path,
            shdrs,
            symtab,
            segments,
            mprotect,
            pltgot,
            init,
            tls_mod_id: None,
            tls_tp_offset: None,
            user_data,
            _marker_tls: PhantomData,
            _marker_arch: PhantomData,
        })
    }
}
