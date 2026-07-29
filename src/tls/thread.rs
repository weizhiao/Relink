use super::{ModuleTls, TlsModuleId, TlsModuleSnapshot, TlsRegistrySnapshot, TlsTpOffset};
use crate::{Result, TlsError};
use alloc::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error},
    vec::Vec,
};
use core::{alloc::Layout, ptr::NonNull};

struct DynamicBlock {
    ptr: NonNull<u8>,
    layout: Layout,
}

unsafe impl Send for DynamicBlock {}

impl DynamicBlock {
    fn new(module: &TlsModuleSnapshot) -> Result<Self> {
        let layout = Layout::from_size_align(module.info.memsz.max(1), module.info.align.max(1))
            .map_err(|_| TlsError::InvalidInfo)?;
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) })
            .unwrap_or_else(|| handle_alloc_error(layout));
        if module.info.filesz != 0 {
            let initialized: Result<()> = module
                .source
                .as_ref()
                .ok_or_else(|| TlsError::TemplateUnavailable.into())
                .and_then(|source| {
                    source.with_image(&mut |image| {
                        if image.len() != module.info.filesz {
                            return Err(TlsError::ModuleMismatch.into());
                        }
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                image.as_ptr(),
                                ptr.as_ptr(),
                                image.len(),
                            )
                        };
                        Ok(())
                    })
                });
            if let Err(error) = initialized {
                unsafe { dealloc(ptr.as_ptr(), layout) };
                return Err(error);
            }
        }
        Ok(Self { ptr, layout })
    }
}

impl Drop for DynamicBlock {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

enum DtvEntry {
    Static(usize),
    Dynamic {
        module: TlsModuleSnapshot,
        block: Option<DynamicBlock>,
    },
}

impl DtvEntry {
    #[inline]
    fn address(&self) -> Option<usize> {
        match self {
            Self::Static(address) => Some(*address),
            Self::Dynamic { block, .. } => block.as_ref().map(|block| block.ptr.as_ptr() as usize),
        }
    }
}

#[derive(Default)]
struct DtvSlot {
    generation: usize,
    entry: Option<DtvEntry>,
}

/// Logical per-thread DTV containing module addresses and dynamic block ownership.
///
/// This type does not define a target architecture's ABI-visible DTV layout.
pub struct ThreadDtv {
    generation: usize,
    slots: Vec<DtvSlot>,
}

impl ThreadDtv {
    /// Creates an empty per-thread DTV.
    pub const fn new() -> Self {
        Self {
            generation: 0,
            slots: Vec::new(),
        }
    }

    /// Returns the registry generation represented by this DTV.
    #[inline]
    pub const fn generation(&self) -> usize {
        self.generation
    }

    /// Synchronizes this DTV with a module registry snapshot.
    ///
    /// `prepare_static` returns the current thread's initialized block for a
    /// static module. Dynamic module metadata is retained for lazy allocation.
    pub fn sync(
        &mut self,
        snapshot: &TlsRegistrySnapshot,
        mut prepare_static: impl FnMut(TlsTpOffset, &TlsModuleSnapshot) -> Result<usize>,
    ) -> Result<()> {
        self.slots
            .resize_with(snapshot.slots.len(), DtvSlot::default);
        for (index, module_slot) in snapshot.slots.iter().enumerate().skip(1) {
            let slot = &mut self.slots[index];
            if slot.generation == module_slot.generation {
                continue;
            }
            // Registration precedes relocation, so another module may be
            // usable while this slot is still waiting for its final image.
            if module_slot
                .module
                .as_ref()
                .is_some_and(|module| module.info.filesz != 0 && module.source.is_none())
            {
                continue;
            }

            let entry = match &module_slot.module {
                Some(module) => match module.tls {
                    ModuleTls::Static { tp_offset, .. } => {
                        Some(DtvEntry::Static(prepare_static(tp_offset, module)?))
                    }
                    ModuleTls::Dynamic { .. } => Some(DtvEntry::Dynamic {
                        module: module.clone(),
                        block: None,
                    }),
                },
                None => None,
            };
            slot.entry = entry;
            slot.generation = module_slot.generation;
        }
        self.generation = snapshot.generation;
        Ok(())
    }

    /// Returns a module's TLS block, allocating dynamic TLS on first use.
    pub fn resolve(&mut self, mod_id: TlsModuleId) -> Result<usize> {
        let entry = self
            .slots
            .get_mut(mod_id.get())
            .and_then(|slot| slot.entry.as_mut())
            .ok_or(TlsError::InvalidModuleId { mod_id })?;
        match entry {
            DtvEntry::Static(address) => Ok(*address),
            DtvEntry::Dynamic { module, block } => {
                if block.is_none() {
                    *block = Some(DynamicBlock::new(module)?);
                }
                Ok(block
                    .as_ref()
                    .expect("dynamic TLS block was just initialized")
                    .ptr
                    .as_ptr() as usize)
            }
        }
    }

    /// Returns an already resolved module address.
    pub fn get(&self, mod_id: TlsModuleId) -> Option<usize> {
        self.slots
            .get(mod_id.get())?
            .entry
            .as_ref()
            .and_then(DtvEntry::address)
    }
}

impl Default for ThreadDtv {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sync::{Arc, arc_unsize},
        tls::{TlsImageProvider, TlsImageSource, TlsInfo, TlsRegistry, TlsStorage},
    };

    struct TestImage;

    impl TlsImageProvider for TestImage {
        fn with_tls_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
            f(&[1, 2, 3, 4])
        }
    }

    fn info() -> TlsInfo {
        TlsInfo {
            vaddr: 0,
            filesz: 0,
            memsz: 16,
            align: 8,
        }
    }

    #[test]
    fn sync_replaces_changed_slots() {
        let mut registry = TlsRegistry::new();
        let module = registry
            .register(info(), TlsStorage::Static(TlsTpOffset::new(-16)), ())
            .unwrap();
        let mod_id = module.mod_id();
        let mut dtv = ThreadDtv::new();

        dtv.sync(&registry.snapshot(), |_, _| Ok(0x1000)).unwrap();
        assert_eq!(dtv.get(mod_id), Some(0x1000));
        assert_eq!(dtv.resolve(mod_id).unwrap(), 0x1000);

        registry.unregister(mod_id);
        dtv.sync(&registry.snapshot(), |_, _| unreachable!())
            .unwrap();
        assert_eq!(dtv.get(mod_id), None);
    }

    #[test]
    fn dynamic_blocks_are_allocated_lazily() {
        let mut registry = TlsRegistry::new();
        let module = registry.register(info(), TlsStorage::Dynamic, ()).unwrap();
        let mod_id = module.mod_id();
        let snapshot = registry.snapshot();
        let mut dtv = ThreadDtv::new();

        dtv.sync(&snapshot, |_, _| unreachable!()).unwrap();
        assert_eq!(dtv.get(mod_id), None);
        let address = dtv.resolve(mod_id).unwrap();
        assert_ne!(address, 0);
        assert_eq!(dtv.resolve(mod_id).unwrap(), address);
    }

    #[test]
    fn sync_skips_modules_until_their_image_is_published() {
        let mut registry = TlsRegistry::new();
        let module = registry
            .register(
                TlsInfo {
                    filesz: 4,
                    memsz: 4,
                    ..TlsInfo::default()
                },
                TlsStorage::Static(TlsTpOffset::new(-4)),
                (),
            )
            .unwrap();
        let mod_id = module.mod_id();
        let mut dtv = ThreadDtv::new();

        dtv.sync(&registry.snapshot(), |_, _| unreachable!())
            .unwrap();
        assert_eq!(dtv.get(mod_id), None);

        let provider = arc_unsize!(Arc::new(TestImage) => dyn TlsImageProvider);
        registry
            .publish(TlsImageSource::new(Arc::downgrade(&provider)), mod_id)
            .unwrap();
        dtv.sync(&registry.snapshot(), |_, _| Ok(0x1000)).unwrap();
        assert_eq!(dtv.get(mod_id), Some(0x1000));
    }
}
