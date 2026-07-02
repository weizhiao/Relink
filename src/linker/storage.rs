use crate::{
    entity::{PrimaryMap, SecondaryMap, entity_ref},
    image::ModuleHandle,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::borrow::Borrow;

/// Stable id for a module key stored in a [`LinkContext`](super::LinkContext).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(usize);
entity_ref!(KeyId);

/// Stable id for a committed module stored in a [`LinkContext`](super::LinkContext).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleId(usize);
entity_ref!(ModuleId);

pub(crate) struct CommittedStorage<
    K,
    D: 'static,
    M = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    key_ids: BTreeMap<K, KeyId>,
    keys: PrimaryMap<KeyId, K>,
    key_modules: SecondaryMap<KeyId, ModuleId>,
    entries: PrimaryMap<ModuleId, Option<StoredEntry<M, Arch, Tls>>>,
    load_order: Vec<ModuleId>,
    marker: core::marker::PhantomData<fn() -> D>,
}

impl<K, D: 'static, M, Arch, Tls> Clone for CommittedStorage<K, D, M, Arch, Tls>
where
    K: Clone,
    M: Clone,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            key_ids: self.key_ids.clone(),
            keys: self.keys.clone(),
            key_modules: self.key_modules.clone(),
            entries: self.entries.clone(),
            load_order: self.load_order.clone(),
            marker: core::marker::PhantomData,
        }
    }
}

impl<K, D: 'static, M, Arch, Tls> CommittedStorage<K, D, M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            key_ids: BTreeMap::new(),
            keys: PrimaryMap::new(),
            key_modules: SecondaryMap::new(),
            entries: PrimaryMap::new(),
            load_order: Vec::new(),
            marker: core::marker::PhantomData,
        }
    }
}

impl<K, D: 'static, M, Arch, Tls> CommittedStorage<K, D, M, Arch, Tls>
where
    K: Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn key(&self, id: KeyId) -> Option<&K> {
        self.keys.get(id)
    }

    #[inline]
    pub(crate) fn key_id<Q>(&self, key: &Q) -> Option<KeyId>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.key_ids.get(key).copied()
    }

    #[inline]
    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.key_id(key).is_some_and(|id| self.contains(id))
    }

    #[inline]
    pub(crate) fn contains(&self, id: KeyId) -> bool {
        self.module_id(id)
            .is_some_and(|module_id| self.contains_module(module_id))
    }

    #[inline]
    pub(crate) fn contains_module(&self, id: ModuleId) -> bool {
        self.entries.get(id).is_some_and(Option::is_some)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.iter().all(|(_, entry)| entry.is_none())
    }

    #[inline]
    pub(crate) fn entry_key_id(&self, id: ModuleId) -> Option<KeyId> {
        Some(self.entries.get(id)?.as_ref()?.entry_key)
    }

    #[inline]
    pub(crate) fn get(&self, id: ModuleId) -> Option<&ModuleHandle<Arch, Tls>> {
        self.entries
            .get(id)
            .and_then(Option::as_ref)
            .map(|entry| &entry.module)
    }

    #[inline]
    pub(crate) fn meta(&self, id: ModuleId) -> Option<&M> {
        self.entries
            .get(id)
            .and_then(Option::as_ref)
            .map(|entry| &entry.meta)
    }

    #[inline]
    pub(crate) fn meta_mut(&mut self, id: ModuleId) -> Option<&mut M> {
        self.entries
            .get_mut(id)
            .and_then(Option::as_mut)
            .map(|entry| &mut entry.meta)
    }

    #[inline]
    pub(crate) fn load_order(&self) -> impl Iterator<Item = ModuleId> + '_ {
        self.load_order
            .iter()
            .copied()
            .filter(|id| self.contains_module(*id))
    }

    #[inline]
    pub(crate) fn aliases(&self) -> impl Iterator<Item = (KeyId, ModuleId)> + '_ {
        self.key_modules.iter().filter_map(|(alias_id, module_id)| {
            let entry_key = self.entry_key_id(*module_id)?;
            (alias_id != entry_key).then_some((alias_id, *module_id))
        })
    }

    #[inline]
    pub(crate) fn direct_deps(&self, id: ModuleId) -> Option<&[KeyId]> {
        let entry = self.entries.get(id)?.as_ref()?;
        Some(entry.direct_deps.as_ref())
    }

    #[inline]
    pub(crate) fn get_by_key(&self, id: KeyId) -> Option<&ModuleHandle<Arch, Tls>> {
        let module_id = self.module_id(id)?;
        self.get(module_id)
    }

    #[inline]
    pub(crate) fn direct_deps_by_key(&self, id: KeyId) -> Option<&[KeyId]> {
        let module_id = self.module_id(id)?;
        self.direct_deps(module_id)
    }

    #[inline]
    pub(crate) fn module_id(&self, id: KeyId) -> Option<ModuleId> {
        self.key_modules.get(id).copied()
    }
}

impl<K, D: 'static, M, Arch, Tls> CommittedStorage<K, D, M, Arch, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    pub(crate) fn intern_key(&mut self, key: K) -> KeyId {
        if let Some(id) = self.key_id(&key) {
            return id;
        }

        let id = self.keys.push(key.clone());
        let previous = self.key_ids.insert(key, id);
        debug_assert!(previous.is_none(), "interned key inserted twice");
        id
    }

    pub(crate) fn add_alias(&mut self, module_id: ModuleId, alias: K) {
        assert!(
            self.contains_module(module_id),
            "alias target id must resolve to a committed module"
        );
        let alias_id = self.key_id(&alias);
        let existing_module = alias_id.and_then(|id| self.module_id(id));
        debug_assert!(
            existing_module.is_none() || existing_module == Some(module_id),
            "alias key must not already resolve to a different module"
        );
        let resolved_alias_id = alias_id.unwrap_or_else(|| self.intern_key(alias));
        self.key_modules.insert(resolved_alias_id, module_id);
    }

    #[inline]
    pub(crate) fn insert_new(
        &mut self,
        id: KeyId,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[KeyId]>,
        meta: M,
    ) -> ModuleId {
        assert!(
            self.keys.get(id).is_some(),
            "linked storage inserted an unknown key id"
        );
        assert!(
            self.key_modules.get(id).is_none(),
            "linked storage inserted a duplicate key"
        );
        let module_id = self.entries.push(Some(StoredEntry {
            entry_key: id,
            module,
            direct_deps,
            meta,
        }));
        self.key_modules.insert(id, module_id);
        self.load_order.push(module_id);
        module_id
    }

    #[inline]
    pub(crate) fn remove(
        &mut self,
        id: ModuleId,
    ) -> Option<(ModuleHandle<Arch, Tls>, Box<[KeyId]>, M)> {
        let removed = self.entries.get_mut(id)?.take()?;
        let aliases = self
            .key_modules
            .iter()
            .filter_map(|(key_id, existing)| (*existing == id).then_some(key_id))
            .collect::<Vec<_>>();
        for key_id in aliases {
            self.key_modules.remove(key_id);
        }
        if let Some(idx) = self.load_order.iter().position(|existing| *existing == id) {
            self.load_order.remove(idx);
        }
        Some((removed.module, removed.direct_deps, removed.meta))
    }
}

struct StoredEntry<
    M = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    entry_key: KeyId,
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[KeyId]>,
    meta: M,
}

impl<M, Arch, Tls> Clone for StoredEntry<M, Arch, Tls>
where
    M: Clone,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            entry_key: self.entry_key,
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
            meta: self.meta.clone(),
        }
    }
}
