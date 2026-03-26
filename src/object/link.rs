use crate::{
    Result,
    arch::object::ObjectRelocator,
    elf::ElfRelType,
    image::RawObject,
    loader::LifecycleContext,
    logging,
    relocation::{RelocArtifacts, RelocHelper, RelocationHandler, SymbolLookup},
};

use super::layout::PltGotSection;
use alloc::{boxed::Box, vec::Vec};

pub(crate) struct ObjectRelocation {
    sections: Box<[&'static [ElfRelType]]>,
}

impl ObjectRelocation {
    pub(crate) fn new(sections: Vec<&'static [ElfRelType]>) -> Self {
        Self {
            sections: sections.into_boxed_slice(),
        }
    }
}

impl<D: 'static> RawObject<D> {
    pub(crate) fn link_impl<PreS, PostS, PreH, PostH>(
        mut self,
        scope: &[crate::image::LoadedCore<D>],
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
    ) -> Result<crate::image::LoadedCore<D>>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        logging::debug!("Relocating object: {}", self.core.name());

        let mut helper = RelocHelper::new(
            &self.core,
            scope.to_vec(),
            pre_find,
            post_find,
            pre_handler,
            post_handler,
            self.core.tls_get_addr(),
        );
        for reloc in self.relocation.sections.iter() {
            for rel in *reloc {
                if !helper.handle_pre(rel)?.is_unhandled() {
                    continue;
                }
                ObjectRelocator::relocate(&mut helper, rel, &mut self.pltgot)?;
                helper.handle_post(rel)?;
            }
        }

        let RelocArtifacts { tls_desc_args, .. } = helper.finish(&[]);

        unsafe {
            self.core.set_tls_desc_args(tls_desc_args);
        }

        (self.mprotect)()?;

        logging::trace!("[{}] Executing init functions", self.core.name());
        self.init
            .call(&LifecycleContext::new(None, self.init_array));

        logging::info!("Relocation completed for {}", self.core.name());

        Ok(unsafe { crate::image::LoadedCore::from_core(self.core) })
    }
}

pub(crate) trait ObjectReloc {
    fn relocate<D, PreS, PostS, PreH, PostH>(
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
