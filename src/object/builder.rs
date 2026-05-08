use super::{
    ObjectRelocation,
    layout::{PltGotSection, SectionSegments},
};
use crate::{
    RelocationError, Result,
    elf::{
        ElfHeader, ElfRelEntry, ElfRelType, ElfSectionType, ElfShdr, ElfSymbol, ElfSymbolType,
        SymbolTable,
    },
    loader::{DynLifecycleHandler, LoadHook, LoaderInner},
    os::Mmap,
    relocation::{RelocAddr, RelocationArch},
    segment::{ElfSegments, SegmentBuilder},
    tls::{TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::{borrow::ToOwned, boxed::Box, string::String, vec::Vec};
use core::marker::PhantomData;

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<Tls, D = (), Arch: RelocationArch = crate::arch::NativeArch> {
    pub(crate) name: String,
    pub(crate) symtab: SymbolTable<Arch::Layout>,
    pub(crate) init_array: Option<&'static [fn()]>,
    pub(crate) init_fn: DynLifecycleHandler,
    pub(crate) fini_fn: DynLifecycleHandler,
    pub(crate) segments: ElfSegments,
    pub(crate) relocation: ObjectRelocation<Arch>,
    pub(crate) mprotect: Box<dyn Fn() -> Result<()>>,
    pub(crate) pltgot: PltGotSection,
    pub(crate) tls_mod_id: Option<TlsModuleId>,
    pub(crate) tls_tp_offset: Option<TlsTpOffset>,
    pub(crate) user_data: D,
    _marker_tls: PhantomData<Tls>,
    _marker_arch: PhantomData<Arch>,
}

struct ObjectSectionData<Arch: RelocationArch> {
    symtab: SymbolTable<Arch::Layout>,
    relocation: ObjectRelocation<Arch>,
    init_array: Option<&'static [fn()]>,
}

impl<T, D, Arch> ObjectBuilder<T, D, Arch>
where
    T: TlsResolver,
    Arch: RelocationArch,
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
            return Err(RelocationError::MissingObjectSymbolTable.into());
        }

        Ok(())
    }

    #[inline]
    fn validate_relocation_shdr(shdr: &ElfShdr<Arch::Layout>) -> Result<()> {
        debug_assert!(matches!(
            shdr.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        ));

        debug_assert_eq!(
            shdr.section_type(),
            <ElfRelType<Arch> as ElfRelEntry<Arch::Layout>>::SECTION_TYPE
        );

        let expected = core::mem::size_of::<ElfRelType<Arch>>();
        let found = shdr.sh_entsize();
        debug_assert_eq!(found, expected);

        Ok(())
    }

    fn rebase_loaded_sections(
        shdrs: &mut [ElfShdr<Arch::Layout>],
        pltgot: &mut PltGotSection,
        base: RelocAddr,
    ) {
        shdrs.iter_mut().for_each(|shdr| {
            shdr.set_sh_addr(base.offset(shdr.sh_addr()).into_inner());
        });
        pltgot.rebase(base);
    }

    fn prepare_symbol_table(
        symtab_shdr: &ElfShdr<Arch::Layout>,
        shdrs: &[ElfShdr<Arch::Layout>],
        base: RelocAddr,
    ) -> SymbolTable<Arch::Layout> {
        let symbols: &mut [ElfSymbol<Arch::Layout>] = symtab_shdr.content_mut();
        for symbol in symbols {
            let section_index = symbol.st_shndx();
            if symbol.symbol_type() == ElfSymbolType::FILE || section_index.is_undef() {
                continue;
            }
            let section_base = RelocAddr::new(shdrs[section_index.index()].sh_addr())
                .relative_to(base.into_inner());
            symbol.set_value(section_base.offset(symbol.st_value()).into_inner());
        }

        SymbolTable::from_shdrs(symtab_shdr, shdrs)
    }

    fn prepare_relocation_section(
        relocation_shdr: &ElfShdr<Arch::Layout>,
        shdrs: &[ElfShdr<Arch::Layout>],
        base: RelocAddr,
    ) -> &'static [ElfRelType<Arch>] {
        let rels: &mut [ElfRelType<Arch>] = relocation_shdr.content_mut();
        let section_base = RelocAddr::new(shdrs[relocation_shdr.sh_info() as usize].sh_addr());
        for rel in rels {
            rel.set_offset(
                section_base
                    .offset(rel.r_offset())
                    .relative_to(base.into_inner())
                    .into_inner(),
            );
        }

        relocation_shdr.content()
    }

    fn prepare_init_array(init_array_shdr: &ElfShdr<Arch::Layout>) -> &'static [fn()] {
        let array: &[usize] = init_array_shdr.content_mut();
        unsafe { core::mem::transmute(array) }
    }

    fn prepare_section_data(
        shdrs: &[ElfShdr<Arch::Layout>],
        base: RelocAddr,
    ) -> Result<ObjectSectionData<Arch>> {
        let mut symtab = None;
        let mut relocation = Vec::with_capacity(shdrs.len());
        let mut init_array = None;

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => {
                    symtab = Some(Self::prepare_symbol_table(shdr, shdrs, base))
                }
                ElfSectionType::RELA | ElfSectionType::REL => {
                    relocation.push(Self::prepare_relocation_section(shdr, shdrs, base))
                }
                ElfSectionType::INIT_ARRAY => init_array = Some(Self::prepare_init_array(shdr)),
                _ => {}
            }
        }

        Ok(ObjectSectionData {
            symtab: symtab.ok_or(RelocationError::MissingObjectSymbolTable)?,
            relocation: ObjectRelocation::new(relocation),
            init_array,
        })
    }

    pub(crate) fn new(
        name: String,
        shdrs: &mut [ElfShdr<Arch::Layout>],
        init_fn: DynLifecycleHandler,
        fini_fn: DynLifecycleHandler,
        segments: ElfSegments,
        mprotect: Box<dyn Fn() -> Result<()>>,
        mut pltgot: PltGotSection,
        user_data: D,
    ) -> Result<Self> {
        Self::validate_shdrs(shdrs)?;
        let base = segments.base_addr();
        Self::rebase_loaded_sections(shdrs, &mut pltgot, base);
        let ObjectSectionData {
            symtab,
            relocation,
            init_array,
        } = Self::prepare_section_data(shdrs, base)?;

        Ok(Self {
            name,
            symtab,
            init_fn,
            fini_fn,
            segments,
            mprotect,
            relocation,
            pltgot,
            init_array,
            tls_mod_id: None,
            tls_tp_offset: None,
            user_data,
            _marker_tls: PhantomData,
            _marker_arch: PhantomData,
        })
    }
}

impl<H, D, Arch> LoaderInner<H, D, Arch>
where
    H: LoadHook<Arch::Layout>,
    D: Default + 'static,
    Arch: crate::relocation::RelocationArch,
{
    pub(crate) fn create_object_builder<M, Tls>(
        &mut self,
        _ehdr: ElfHeader<Arch::Layout>,
        shdrs: &mut [ElfShdr<Arch::Layout>],
        mut object: impl crate::input::ElfReader,
    ) -> Result<ObjectBuilder<Tls, D, Arch>>
    where
        M: Mmap,
        Tls: TlsResolver,
    {
        let name = object.file_name().to_owned();
        let (init_fn, fini_fn) = self.lifecycle_handlers();
        let mut shdr_segments =
            SectionSegments::<Arch>::new(shdrs, &mut object, self.page_size::<M>()?.bytes())?;
        let segments = shdr_segments.load_segments::<M>(&mut object)?;
        let pltgot = shdr_segments.take_pltgot();
        let mprotect = Box::new(move || {
            shdr_segments.mprotect::<M>()?;
            Ok(())
        });
        let user_data = D::default();

        ObjectBuilder::new(
            name, shdrs, init_fn, fini_fn, segments, mprotect, pltgot, user_data,
        )
    }
}
