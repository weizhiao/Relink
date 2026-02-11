use crate::{
    Result,
    arch::StaticRelocator,
    elf::ElfRelType,
    image::{LoadedCore, RawObject},
    loader::LifecycleContext,
    relocation::{RelocHelper, RelocationHandler, SymbolLookup},
    segment::section::PltGotSection,
};
use alloc::{boxed::Box, vec::Vec};

pub(crate) struct StaticRelocation {
    relocation: Box<[&'static [ElfRelType]]>,
}

impl StaticRelocation {
    pub(crate) fn new(relocation: Vec<&'static [ElfRelType]>) -> Self {
        Self {
            relocation: relocation.into_boxed_slice(),
        }
    }
}

impl<D: 'static> RawObject<D> {
    pub(crate) fn relocate_impl<PreS, PostS, PreH, PostH>(
        mut self,
        scope: &[LoadedCore<D>],
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
    ) -> Result<LoadedCore<D>>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        #[cfg(feature = "log")]
        log::debug!("Relocating object: {}", self.core.name());

        let mut helper = RelocHelper::new(
            &self.core,
            scope.to_vec(),
            pre_find,
            post_find,
            pre_handler,
            post_handler,
            self.tls_get_addr,
        );

        let mut relocator = StaticRelocator::new(&self.relocation.relocation);
        
        // Prepare relocator (build caches, etc.)
        relocator.prepare(&self.relocation.relocation, &helper);
        
        for reloc in self.relocation.relocation.iter() {
            for rel in *reloc {
                if !helper.handle_pre(rel)? {
                    continue;
                }
                relocator.relocate(&mut helper, rel, &mut self.pltgot)?;
                if !helper.handle_post(rel)? {
                    continue;
                }
            }
        }

        // Set TLS descriptor arguments collected during relocation
        unsafe {
            self.core.set_tls_desc_args(helper.tls_desc_args);
        }

        (self.mprotect)()?;

        #[cfg(feature = "log")]
        log::trace!("[{}] Executing init functions", self.core.name());
        self.init
            .call(&LifecycleContext::new(None, self.init_array));

        #[cfg(feature = "log")]
        log::info!("Relocation completed for {}", self.core.name());

        Ok(unsafe { LoadedCore::from_core(self.core) })
    }
}

pub(crate) trait StaticReloc: Sized {
    /// Create a new relocator instance
    fn new(relocs: &[&'static [ElfRelType]]) -> Self;

    /// Prepare for relocation (build caches, etc.)
    fn prepare<D, PreS, PostS, PreH, PostH>(
        &mut self,
        relocs: &[&'static [ElfRelType]],
        helper: &RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
    ) where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized;

    /// Relocate a single relocation entry
    fn relocate<D, PreS, PostS, PreH, PostH>(
        &mut self,
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType,
        pltgot: &mut PltGotSection,
    ) -> Result<()>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized;

    fn needs_got(_rel_type: u32) -> bool {
        false
    }

    fn needs_plt(_rel_type: u32) -> bool {
        false
    }
}
