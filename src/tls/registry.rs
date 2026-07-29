use super::{ModuleTls, TlsImageSource, TlsInfo, TlsModuleId, TlsTpOffset};
use crate::{Result, TlsError};
use alloc::vec::Vec;

/// Storage selected for one TLS module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsStorage {
    /// The module is allocated lazily through the dynamic thread vector.
    Dynamic,
    /// The module lives at a fixed offset from the thread pointer.
    Static(TlsTpOffset),
}

impl TlsStorage {
    #[inline]
    fn module(self, mod_id: TlsModuleId) -> ModuleTls {
        match self {
            Self::Dynamic => ModuleTls::Dynamic { mod_id },
            Self::Static(tp_offset) => ModuleTls::Static { mod_id, tp_offset },
        }
    }
}

/// Cloneable TLS module metadata used outside a registry lock.
#[derive(Clone, Debug)]
pub struct TlsModuleSnapshot {
    /// TLS segment metadata.
    pub info: TlsInfo,
    /// Registered runtime TLS metadata.
    pub tls: ModuleTls,
    /// Relocated initialization image, when initialization has completed.
    pub source: Option<TlsImageSource>,
}

/// One module slot in a registry snapshot.
#[derive(Clone, Debug)]
pub struct TlsSlotSnapshot {
    /// Generation in which this slot was last changed.
    pub generation: usize,
    /// Module metadata, or `None` when the slot has been unloaded.
    pub module: Option<TlsModuleSnapshot>,
}

/// Consistent snapshot of all registered TLS modules.
#[derive(Clone, Debug)]
pub struct TlsRegistrySnapshot {
    /// Registry generation represented by this snapshot.
    pub generation: usize,
    /// Module slots indexed by [`TlsModuleId`].
    pub slots: Vec<TlsSlotSnapshot>,
}

#[derive(Debug)]
struct TlsModuleRecord<D> {
    info: TlsInfo,
    tls: ModuleTls,
    source: Option<TlsImageSource>,
    data: D,
}

impl<D> TlsModuleRecord<D> {
    fn snapshot(&self) -> TlsModuleSnapshot {
        TlsModuleSnapshot {
            info: self.info,
            tls: self.tls,
            source: self.source.clone(),
        }
    }
}

#[derive(Debug)]
struct TlsSlot<D> {
    generation: usize,
    module: Option<TlsModuleRecord<D>>,
}

/// Architecture-independent registry for TLS module metadata.
///
/// Resolver-specific state can be stored in `D`. Per-thread storage and target
/// ABI details remain the responsibility of the resolver using this registry.
#[derive(Debug)]
pub struct TlsRegistry<D = ()> {
    slots: Vec<TlsSlot<D>>,
    generation: usize,
}

impl<D> TlsRegistry<D> {
    /// Creates an empty registry. Slot zero remains reserved for the TLS ABI.
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            generation: 0,
        }
    }

    /// Returns the current registry generation.
    #[inline]
    pub fn generation(&self) -> usize {
        self.generation
    }

    /// Registers one module and returns its runtime TLS metadata.
    pub fn register(&mut self, info: TlsInfo, storage: TlsStorage, data: D) -> Result<ModuleTls> {
        info.validate()?;
        if self.slots.is_empty() {
            self.slots.push(TlsSlot {
                generation: 0,
                module: None,
            });
        }
        self.generation += 1;
        let index = self
            .slots
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, slot)| slot.module.is_none())
            .map(|(index, _)| index)
            .unwrap_or(self.slots.len());
        let module = storage.module(TlsModuleId::new(index));
        let slot = TlsSlot {
            generation: self.generation,
            module: Some(TlsModuleRecord {
                info,
                tls: module,
                source: None,
                data,
            }),
        };
        if index == self.slots.len() {
            self.slots.push(slot);
        } else {
            self.slots[index] = slot;
        }
        Ok(module)
    }

    /// Publishes the relocated initialization image for a registered module.
    pub fn publish(&mut self, source: TlsImageSource, mod_id: TlsModuleId) -> Result<()> {
        let slot = self
            .slots
            .get_mut(mod_id.get())
            .ok_or(TlsError::InvalidModuleId { mod_id })?;
        let record = slot
            .module
            .as_mut()
            .ok_or(TlsError::InvalidModuleId { mod_id })?;
        if record.source.is_some() {
            return Err(TlsError::AlreadyPublished { mod_id }.into());
        }

        self.generation += 1;
        record.source = Some(source);
        slot.generation = self.generation;
        Ok(())
    }

    /// Unregisters a module and drops its resolver-specific state.
    pub fn unregister(&mut self, mod_id: TlsModuleId) -> bool {
        let Some(slot) = self.slots.get_mut(mod_id.get()) else {
            return false;
        };
        if slot.module.is_none() {
            return false;
        }
        self.generation += 1;
        slot.generation = self.generation;
        slot.module = None;
        true
    }

    /// Returns a cloneable snapshot of one module.
    pub fn module(&self, mod_id: TlsModuleId) -> Option<TlsModuleSnapshot> {
        self.slots
            .get(mod_id.get())?
            .module
            .as_ref()
            .map(TlsModuleRecord::snapshot)
    }

    /// Returns the TLS segment metadata for one module.
    pub fn info(&self, mod_id: TlsModuleId) -> Option<TlsInfo> {
        self.slots
            .get(mod_id.get())?
            .module
            .as_ref()
            .map(|module| module.info)
    }

    /// Returns resolver-specific state for one module.
    pub fn data(&self, mod_id: TlsModuleId) -> Option<&D> {
        self.slots
            .get(mod_id.get())?
            .module
            .as_ref()
            .map(|module| &module.data)
    }

    /// Returns resolver-specific state for one module.
    pub fn data_mut(&mut self, mod_id: TlsModuleId) -> Option<&mut D> {
        self.slots
            .get_mut(mod_id.get())?
            .module
            .as_mut()
            .map(|module| &mut module.data)
    }

    /// Takes a consistent snapshot when the registry changed after `generation`.
    pub fn snapshot_since(&self, generation: usize) -> Option<TlsRegistrySnapshot> {
        if self.generation == generation {
            return None;
        }
        Some(self.snapshot())
    }

    /// Takes a consistent snapshot of the registry.
    pub fn snapshot(&self) -> TlsRegistrySnapshot {
        TlsRegistrySnapshot {
            generation: self.generation,
            slots: self
                .slots
                .iter()
                .map(|slot| TlsSlotSnapshot {
                    generation: slot.generation,
                    module: slot.module.as_ref().map(TlsModuleRecord::snapshot),
                })
                .collect(),
        }
    }
}

impl<D> Default for TlsRegistry<D> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sync::Arc,
        tls::{TlsImageProvider, tls_image_provider_handle},
    };

    struct TestImage;

    impl TlsImageProvider for TestImage {
        fn with_tls_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
            f(&[0; 4])
        }
    }

    fn info() -> TlsInfo {
        TlsInfo {
            vaddr: 0,
            filesz: 4,
            memsz: 8,
            align: 4,
        }
    }

    #[test]
    fn unregister_changes_generation_and_reuses_slot() {
        let mut registry = TlsRegistry::new();
        let first = registry.register(info(), TlsStorage::Dynamic, ()).unwrap();
        let first_id = first.mod_id();
        assert_eq!(first_id.get(), 1);

        let generation = registry.generation();
        assert!(registry.snapshot_since(generation).is_none());
        assert!(registry.unregister(first_id));
        assert!(registry.generation() > generation);
        assert!(registry.module(first_id).is_none());

        let offset = TlsTpOffset::new(-8);
        let second = registry
            .register(info(), TlsStorage::Static(offset), ())
            .unwrap();
        assert_eq!(second.mod_id(), first_id);
        assert_eq!(second.tp_offset(), Some(offset));
    }

    #[test]
    fn rejects_invalid_tls_info() {
        let mut registry = TlsRegistry::new();
        let invalid = TlsInfo { align: 3, ..info() };
        assert!(registry.register(invalid, TlsStorage::Dynamic, ()).is_err());
        assert_eq!(registry.generation(), 0);
    }

    #[test]
    fn rejects_repeated_publication() {
        let mut registry = TlsRegistry::new();
        let module = registry.register(info(), TlsStorage::Dynamic, ()).unwrap();
        let provider = tls_image_provider_handle(Arc::new(TestImage));
        let source = TlsImageSource::new(Arc::downgrade(&provider));

        registry.publish(source.clone(), module.mod_id()).unwrap();
        let generation = registry.generation();
        assert!(registry.publish(source, module.mod_id()).is_err());
        assert_eq!(registry.generation(), generation);
    }
}
