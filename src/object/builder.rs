use super::{
    CustomHash, ObjectRelocation,
    layout::{ObjectSegmentView, ObjectSegments, PltGotSection, SectionSegments},
};
use crate::{
    ParseShdrError, RelocationError, Result,
    elf::{
        ElfRelEntry, ElfRelType, ElfSectionType, ElfSections, ElfShdr, ElfSymbol, ElfSymbolType,
        Lifecycle, SymbolTable,
    },
    input::PathBuf,
    loader::LoaderInner,
    observer::LoadObserver,
    os::{HostRegion, RegionAccess, VmAddr},
    relocation::ObjectRelocationArch,
    tls::{TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::{boxed::Box, vec::Vec};
use core::{marker::PhantomData, mem::size_of};

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<
    Tls,
    D = (),
    Arch: ObjectRelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) path: PathBuf,
    pub(crate) symtab: SymbolTable<Arch::Layout, CustomHash>,
    pub(crate) init: Lifecycle,
    pub(crate) segments: ObjectSegments<R>,
    pub(crate) relocation: ObjectRelocation<Arch>,
    pub(crate) mprotect: Box<dyn for<'segments> Fn(&ObjectSegmentView<'segments, R>) -> Result<()>>,
    pub(crate) pltgot: PltGotSection,
    pub(crate) tls_mod_id: Option<TlsModuleId>,
    pub(crate) tls_tp_offset: Option<TlsTpOffset>,
    pub(crate) user_data: D,
    _marker_tls: PhantomData<Tls>,
    _marker_arch: PhantomData<Arch>,
}

struct ObjectSectionData<Arch: ObjectRelocationArch> {
    symtab: SymbolTable<Arch::Layout, CustomHash>,
    relocation: ObjectRelocation<Arch>,
    init: Lifecycle,
}

impl<T, D, Arch, R> ObjectBuilder<T, D, Arch, R>
where
    T: TlsResolver,
    Arch: ObjectRelocationArch,
    R: RegionAccess,
{
    #[inline]
    pub(crate) fn validate_shdrs(shdrs: &[ElfShdr<Arch::Layout>]) -> Result<()> {
        let mut has_symtab = false;

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => has_symtab = true,
                ElfSectionType::REL | ElfSectionType::RELA => Self::validate_relocation_shdr(shdr)?,
                _ => {}
            }
        }

        if !has_symtab {
            return Err(RelocationError::MissingSymbolTable.into());
        }

        Ok(())
    }

    #[inline]
    fn validate_relocation_shdr(shdr: &ElfShdr<Arch::Layout>) -> Result<()> {
        debug_assert!(matches!(
            shdr.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        ));

        if shdr.section_type() != <ElfRelType<Arch> as ElfRelEntry<Arch::Layout>>::SECTION_TYPE {
            return Err(ParseShdrError::malformed(
                "relocation section type does not match target architecture",
            )
            .into());
        }

        let expected = size_of::<ElfRelType<Arch>>();
        let found = shdr.sh_entsize();
        if found != expected {
            return Err(ParseShdrError::malformed("relocation entry size mismatch").into());
        }
        if !shdr.sh_size().is_multiple_of(expected) {
            return Err(ParseShdrError::malformed(
                "relocation section size is not a multiple of entry size",
            )
            .into());
        }

        Ok(())
    }

    fn prepare_symbol_table(
        symtab_shdr: &ElfShdr<Arch::Layout>,
        shdrs: &[ElfShdr<Arch::Layout>],
        base: VmAddr,
    ) -> SymbolTable<Arch::Layout, CustomHash> {
        let symbols: &mut [ElfSymbol<Arch::Layout>] = symtab_shdr.content_mut();
        for symbol in symbols {
            let section_index = symbol.st_shndx();
            if symbol.symbol_type() == ElfSymbolType::FILE || section_index.is_undef() {
                continue;
            }
            let section_base = shdrs[section_index.index()]
                .sh_addr()
                .wrapping_sub(base.get());
            symbol.set_value(section_base.wrapping_add(symbol.st_value()));
        }

        SymbolTable::from_shdrs(symtab_shdr, shdrs)
    }

    fn prepare_relocation_section(
        relocation_shdr: &ElfShdr<Arch::Layout>,
        shdrs: &[ElfShdr<Arch::Layout>],
        base: VmAddr,
    ) -> &'static [ElfRelType<Arch>] {
        let rels: &mut [ElfRelType<Arch>] = relocation_shdr.content_mut();
        let section_base = VmAddr::new(shdrs[relocation_shdr.sh_info() as usize].sh_addr());
        for rel in rels {
            rel.set_offset((section_base + rel.r_offset()).wrapping_offset_from(base));
        }

        relocation_shdr.content()
    }

    fn prepare_init_array(init_array_shdr: &ElfShdr<Arch::Layout>) -> Lifecycle {
        let array: &[usize] = init_array_shdr.content_mut();
        let array = array.iter().copied().map(VmAddr::new).collect::<Box<[_]>>();
        Lifecycle::new(None, Some(array))
    }

    fn prepare_section_data(
        shdrs: &[ElfShdr<Arch::Layout>],
        base: VmAddr,
    ) -> Result<ObjectSectionData<Arch>> {
        let mut symtab = None;
        let mut relocation = Vec::with_capacity(shdrs.len());
        let mut init = Lifecycle::new(None, None);

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => {
                    symtab = Some(Self::prepare_symbol_table(shdr, shdrs, base))
                }
                ElfSectionType::RELA | ElfSectionType::REL => {
                    relocation.push(Self::prepare_relocation_section(shdr, shdrs, base))
                }
                ElfSectionType::INIT_ARRAY => init = Self::prepare_init_array(shdr),
                _ => {}
            }
        }

        Ok(ObjectSectionData {
            symtab: symtab.ok_or(RelocationError::MissingSymbolTable)?,
            relocation: ObjectRelocation::new(relocation),
            init,
        })
    }

    pub(crate) fn new(
        path: PathBuf,
        shdrs: &mut [ElfShdr<Arch::Layout>],
        segments: ObjectSegments<R>,
        mprotect: Box<dyn for<'segments> Fn(&ObjectSegmentView<'segments, R>) -> Result<()>>,
        pltgot: PltGotSection,
        user_data: D,
    ) -> Result<Self> {
        let base = segments.core().base();
        let ObjectSectionData {
            symtab,
            relocation,
            init,
        } = Self::prepare_section_data(shdrs, base)?;

        Ok(Self {
            path,
            symtab,
            segments,
            mprotect,
            relocation,
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

impl<Obs, D, Arch, M> LoaderInner<Obs, D, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Default + 'static,
    Arch: crate::relocation::ObjectRelocationArch,
    M: crate::os::Mmap,
{
    pub(crate) fn create_object_builder<Tls>(
        &mut self,
        mut sections: ElfSections<'_, Arch::Layout>,
        object: impl crate::input::ElfReader,
        user_data: D,
    ) -> Result<ObjectBuilder<Tls, D, Arch, M::Region>>
    where
        Tls: TlsResolver,
    {
        let path = PathBuf::from(object.path());
        let page_size = self.page_size()?.bytes();
        ObjectBuilder::<Tls, D, Arch, M::Region>::validate_shdrs(sections.headers())?;
        let mut shdr_segments = SectionSegments::<Arch>::new::<D, _>(
            &mut sections,
            &object,
            page_size,
            &mut self.observer,
        )?;
        let mapper = self.mapper();
        let segments = shdr_segments.load_segments(mapper, &object)?;
        let mut pltgot = shdr_segments.take_pltgot();
        shdr_segments.rebase_loaded_sections(sections.headers_mut(), &mut pltgot, &segments);
        let mprotect = Box::new(move |segments: &ObjectSegmentView<'_, M::Region>| {
            shdr_segments.mprotect(segments)
        });

        ObjectBuilder::new(
            path,
            sections.headers_mut(),
            segments,
            mprotect,
            pltgot,
            user_data,
        )
    }
}
