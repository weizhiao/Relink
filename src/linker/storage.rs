use crate::{
    LinkContextError, LinkerError, Result,
    arch::NativeArch,
    entity::{PrimaryMap, entity_ref},
    image::{LookupScope, ModuleHandle, ModuleInstanceId},
    input::{ModuleSourceId, Path, PathBuf},
    relocation::RelocationArch,
    runtime::DomainId,
    sync::{Arc, AtomicUsize, Ordering},
    tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
    string::String,
    vec::Vec,
};
use core::{
    borrow::Borrow,
    fmt::{self, Display},
    ops::Deref,
};

/// Logical name used to address a module inside a [`LinkContext`](super::LinkContext).
///
/// A key is an ordered lookup name such as a resolved path, `DT_SONAME`, or
/// `DT_NEEDED` name. Physical module identity is tracked separately by
/// [`ModuleSourceId`], so several modules may be registered under one key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleKey(Arc<str>);

impl ModuleKey {
    /// Creates a key from a loader-visible name or path.
    #[inline]
    pub fn new(value: impl AsRef<str>) -> Self {
        Self(Arc::from(value.as_ref()))
    }

    /// Returns the key as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for ModuleKey {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ModuleKey {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ModuleKey {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Display for ModuleKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ModuleKey {
    #[inline]
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ModuleKey {
    #[inline]
    fn from(value: String) -> Self {
        Self(Arc::from(value))
    }
}

impl From<&Path> for ModuleKey {
    #[inline]
    fn from(value: &Path) -> Self {
        Self::new(value.as_str())
    }
}

impl From<PathBuf> for ModuleKey {
    #[inline]
    fn from(value: PathBuf) -> Self {
        Self(Arc::from(value.into_string()))
    }
}

/// Symbol-namespace identity of a [`LinkContext`](super::LinkContext).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextId(usize);

impl ContextId {
    #[inline]
    pub(crate) fn fresh() -> Self {
        static NEXT_CONTEXT_ID: AtomicUsize = AtomicUsize::new(1);

        let id = NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "link context id counter overflowed");
        Self(id)
    }
}

impl Display for ContextId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::linker) struct ModuleSlot(usize);
entity_ref!(ModuleSlot);

/// Identity of one committed module incarnation in a
/// [`LinkContext`](super::LinkContext).
///
/// An id becomes stale after its module is unloaded, even if the same key is
/// loaded again later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleId {
    context: ContextId,
    slot: ModuleSlot,
    generation: u32,
}

impl ModuleId {
    #[inline]
    pub(in crate::linker) const fn from_slot(
        context: ContextId,
        slot: ModuleSlot,
        generation: u32,
    ) -> Self {
        Self {
            context,
            slot,
            generation,
        }
    }

    #[inline]
    pub(in crate::linker) const fn context(self) -> ContextId {
        self.context
    }
}

impl Display for ModuleId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} in link context {}",
            self.slot.0, self.generation, self.context
        )
    }
}

/// One direct acquisition of a committed module.
///
/// A lease is created by [`LinkContext::insert`](super::LinkContext::insert),
/// [`LinkContext::insert_batch`](super::LinkContext::insert_batch),
/// [`LinkContext::acquire`](super::LinkContext::acquire), or a linker load. It is
/// intentionally neither [`Clone`] nor [`Copy`]; pass it to
/// [`LinkContext::release`](super::LinkContext::release) exactly once when the
/// direct use ends.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a module lease must eventually be released"]
pub struct ModuleLease {
    id: ModuleId,
}

impl ModuleLease {
    #[inline]
    pub(in crate::linker) const fn new(id: ModuleId) -> Self {
        Self { id }
    }

    /// Returns the identity of the acquired module.
    #[inline]
    pub const fn id(&self) -> ModuleId {
        self.id
    }
}

#[derive(Clone, Copy)]
pub(in crate::linker) struct CommittedModule<'a, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    entry: &'a StoredEntry<Meta, Arch, Tls>,
}

impl<'a, Meta, Arch, Tls> CommittedModule<'a, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(in crate::linker) const fn entry_key(&self) -> &'a ModuleKey {
        &self.entry.entry_key
    }

    #[inline]
    pub(crate) fn handle(&self) -> &'a ModuleHandle<Arch, Tls> {
        &self.entry.module
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> &'a [ModuleSlot] {
        &self.entry.direct_deps
    }

    #[inline]
    pub(crate) const fn scope(&self) -> &'a LookupScope<Arch, Tls> {
        &self.entry.scope
    }

    #[inline]
    pub(crate) const fn is_root(&self) -> bool {
        self.entry.pinned || self.entry.roots != 0
    }

    #[inline]
    pub(crate) const fn meta(&self) -> &'a Meta {
        &self.entry.meta
    }
}

pub(in crate::linker) struct CommittedModuleMut<'a, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    entry: &'a mut StoredEntry<Meta, Arch, Tls>,
}

impl<'a, Meta, Arch, Tls> CommittedModuleMut<'a, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn acquire_root(&mut self) {
        self.acquire_roots(1);
    }

    #[inline]
    pub(crate) fn acquire_roots(&mut self, count: usize) {
        self.entry.roots = self
            .entry
            .roots
            .checked_add(count)
            .expect("module acquisition count overflow");
    }

    #[inline]
    pub(crate) fn release_root(&mut self) -> usize {
        self.entry.roots = self
            .entry
            .roots
            .checked_sub(1)
            .expect("module lease must represent a direct acquisition");
        self.entry.roots
    }

    #[inline]
    pub(crate) fn pin_root(&mut self) {
        self.release_root();
        self.entry.pinned = true;
    }

    #[inline]
    pub(crate) fn meta_mut(self) -> &'a mut Meta {
        &mut self.entry.meta
    }
}

pub(crate) struct CommittedStorage<
    Meta = (),
    Arch: RelocationArch = NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    context: ContextId,
    domain: DomainId,
    bindings: BTreeMap<ModuleKey, Vec<ModuleSlot>>,
    sources: BTreeMap<ModuleSourceId, ModuleSlot>,
    entries: PrimaryMap<ModuleSlot, ModuleCell<Meta, Arch, Tls>>,
    lifecycle: Vec<ModuleSlot>,
}

impl<Meta, Arch, Tls> CommittedStorage<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(context: ContextId, domain: DomainId) -> Self {
        Self {
            context,
            domain,
            bindings: BTreeMap::new(),
            sources: BTreeMap::new(),
            entries: PrimaryMap::new(),
            lifecycle: Vec::new(),
        }
    }

    #[inline]
    pub(crate) const fn context(&self) -> ContextId {
        self.context
    }

    #[inline]
    pub(crate) const fn domain(&self) -> DomainId {
        self.domain
    }

    pub(crate) fn ensure_domain(&self, domain: DomainId) -> Result<()> {
        self.domain.ensure(domain)
    }

    #[inline]
    pub(in crate::linker) fn make_module_id(&self, slot: ModuleSlot) -> ModuleId {
        ModuleId::from_slot(self.context, slot, self.entries[slot].generation)
    }

    #[inline]
    pub(in crate::linker) fn module_slot(&self, id: ModuleId) -> Result<ModuleSlot> {
        if id.context != self.context {
            return Err(
                LinkerError::context(LinkContextError::ModuleContextMismatch {
                    id,
                    expected: self.context,
                })
                .into(),
            );
        }
        self.entries
            .get(id.slot)
            .filter(|entry| entry.generation == id.generation && entry.entry.is_some())
            .map(|_| id.slot)
            .ok_or_else(|| LinkerError::context(LinkContextError::StaleModuleId { id }).into())
    }

    #[inline]
    pub(in crate::linker) fn contains_id(&self, id: ModuleId) -> Result<bool> {
        if id.context != self.context {
            return Err(
                LinkerError::context(LinkContextError::ModuleContextMismatch {
                    id,
                    expected: self.context,
                })
                .into(),
            );
        }
        Ok(self
            .entries
            .get(id.slot)
            .is_some_and(|entry| entry.generation == id.generation && entry.entry.is_some()))
    }

    #[inline]
    pub(in crate::linker) fn module(
        &self,
        slot: ModuleSlot,
    ) -> Option<CommittedModule<'_, Meta, Arch, Tls>> {
        let cell = self.entries.get(slot)?;
        let entry = cell.entry.as_ref()?;
        Some(CommittedModule { entry })
    }

    #[inline]
    pub(crate) fn module_mut(
        &mut self,
        slot: ModuleSlot,
    ) -> Option<CommittedModuleMut<'_, Meta, Arch, Tls>> {
        match self.entries.get_mut(slot) {
            Some(ModuleCell {
                entry: Some(entry), ..
            }) => Some(CommittedModuleMut { entry }),
            _ => None,
        }
    }

    #[inline]
    pub(in crate::linker) fn module_for_key(&self, key: &str) -> Option<ModuleSlot> {
        let module = self.bindings.get(key)?.first().copied()?;
        debug_assert!(
            self.contains_module(module),
            "key bindings must only contain committed modules"
        );
        Some(module)
    }

    #[inline]
    pub(in crate::linker) fn contains_module(&self, slot: ModuleSlot) -> bool {
        self.entries
            .get(slot)
            .is_some_and(|cell| cell.entry.is_some())
    }

    #[inline]
    pub(in crate::linker) fn generation(&self, slot: ModuleSlot) -> u32 {
        self.entries[slot].generation
    }

    #[inline]
    pub(in crate::linker) fn module_for_source(
        &self,
        source: ModuleSourceId,
    ) -> Option<ModuleSlot> {
        self.sources.get(&source).copied()
    }

    #[inline]
    pub(in crate::linker) fn module_for_binding(
        &self,
        binding: ModuleInstanceId,
    ) -> Option<ModuleSlot> {
        let slot = self.module_for_source(binding.source_id())?;
        (binding == self.module(slot)?.handle().state().instance_id()).then_some(slot)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.lifecycle.is_empty()
    }

    #[inline]
    pub(crate) fn lifecycle(&self) -> impl DoubleEndedIterator<Item = ModuleSlot> + '_ {
        self.lifecycle.iter().copied()
    }

    pub(crate) fn bind_key(&mut self, key: ModuleKey, module: ModuleSlot) {
        assert!(
            self.contains_module(module),
            "key bindings must refer to committed modules"
        );
        let entry_key = &self.entries[module]
            .entry
            .as_ref()
            .expect("key bindings must refer to committed modules")
            .entry_key;
        let is_alias = entry_key != &key;
        let mut alias = None;
        let inserted = match self.bindings.entry(key) {
            Entry::Vacant(entry) => {
                if is_alias {
                    alias = Some(entry.key().clone());
                }
                entry.insert(Vec::from([module]));
                true
            }
            Entry::Occupied(mut entry) => {
                if entry.get().contains(&module) {
                    false
                } else {
                    if is_alias {
                        alias = Some(entry.key().clone());
                    }
                    entry.get_mut().push(module);
                    true
                }
            }
        };
        if inserted && let Some(alias) = alias {
            let entry = self.entries[module]
                .entry
                .as_mut()
                .expect("key bindings must refer to committed modules");
            debug_assert!(!entry.aliases.contains(&alias));
            entry.aliases.push(alias);
        }
    }

    pub(crate) fn extend_lifecycle(&mut self, order: &[ModuleSlot]) {
        debug_assert!(
            order
                .iter()
                .enumerate()
                .all(|(idx, slot)| !order[..idx].contains(slot)),
            "lifecycle entries must be unique"
        );
        debug_assert!(
            order.iter().all(|slot| !self.lifecycle.contains(slot)),
            "lifecycle entries must only be recorded once"
        );
        self.lifecycle.extend_from_slice(order);
    }

    pub(crate) fn alloc_module(&mut self) -> ModuleSlot {
        self.entries.push(ModuleCell {
            generation: 0,
            entry: None,
        })
    }

    pub(crate) fn insert(&mut self, slot: ModuleSlot, entry: StoredEntry<Meta, Arch, Tls>) {
        let source = entry.module.source_id();
        assert!(
            !self.sources.contains_key(&source),
            "module source is already committed"
        );
        let cell = &mut self.entries[slot];
        assert!(cell.entry.is_none(), "module slot is already committed");
        cell.advance_generation();
        cell.entry = Some(entry);
        self.sources.insert(source, slot);
    }

    #[inline]
    pub(crate) fn remove(
        &mut self,
        slot: ModuleSlot,
    ) -> (ModuleHandle<Arch, Tls>, LookupScope<Arch, Tls>, Meta) {
        let entry = {
            let cell = &mut self.entries[slot];
            let entry = cell
                .entry
                .take()
                .expect("unload order must refer to a committed module");
            cell.advance_generation();
            entry
        };
        for key in core::iter::once(&entry.entry_key).chain(&entry.aliases) {
            let empty = {
                let modules = self
                    .bindings
                    .get_mut(key)
                    .expect("module key must have a binding list");
                modules.retain(|candidate| *candidate != slot);
                modules.is_empty()
            };
            if empty {
                self.bindings.remove(key);
            }
        }
        let indexed = self
            .sources
            .remove(&entry.module.source_id())
            .expect("committed module must have a source entry");
        assert_eq!(indexed, slot, "module source must refer to its slot");
        (entry.module, entry.scope, entry.meta)
    }

    pub(crate) fn prune_lifecycle(&mut self) {
        let entries = &self.entries;
        self.lifecycle
            .retain(|slot| entries.get(*slot).is_some_and(|cell| cell.entry.is_some()));
    }
}

struct ModuleCell<Meta = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    // Incremented on publication and removal to guard transactional references
    // and make ids stale as soon as a module is unloaded.
    generation: u32,
    entry: Option<StoredEntry<Meta, Arch, Tls>>,
}

impl<Meta, Arch: RelocationArch, Tls: TlsResolver<Arch>> ModuleCell<Meta, Arch, Tls> {
    #[inline]
    fn advance_generation(&mut self) {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("module generation overflowed");
    }
}

pub(in crate::linker) struct StoredEntry<
    Meta = (),
    Arch: RelocationArch = NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    entry_key: ModuleKey,
    aliases: Vec<ModuleKey>,
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[ModuleSlot]>,
    scope: LookupScope<Arch, Tls>,
    roots: usize,
    pinned: bool,
    meta: Meta,
}

impl<Meta, Arch, Tls> StoredEntry<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(in crate::linker) fn new(
        entry_key: ModuleKey,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleSlot]>,
        scope: LookupScope<Arch, Tls>,
        roots: usize,
        meta: Meta,
    ) -> Self {
        Self {
            entry_key,
            aliases: Vec::new(),
            module,
            direct_deps,
            scope,
            roots,
            pinned: false,
            meta,
        }
    }
}

impl<Meta, Arch, Tls> Drop for CommittedStorage<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn drop(&mut self) {
        // ModuleHandle performs the release. Taking entries here only preserves
        // dependent-before-dependency finalization for modules without scopes.
        for slot in self.lifecycle.iter().rev().copied() {
            if let Some(cell) = self.entries.get_mut(slot) {
                let _ = cell.entry.take();
            }
        }
    }
}
