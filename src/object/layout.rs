use super::ObjectSections;
use crate::{
    AlignedBytes, MmapError, ParseShdrError, Result,
    arch::object::{PLT_ENTRY, PLT_ENTRY_SIZE},
    elf::{
        ElfLayout, ElfRelEntry, ElfRelType, ElfSectionFlags, ElfSectionId, ElfSectionType, ElfShdr,
    },
    input::{ElfReader, ElfReaderExt},
    memory::{ImageMemory, RegionAccess, VmAddr, VmOffset, rounddown, roundup},
    observer::{LoadObserver, SectionLayoutEvent},
    os::{MapFlags, Mmap, ProtFlags},
    relocation::{ObjectRelocationArch, RelocationArch},
    segment::{ElfSegment, ElfSegments, FileMapInfo, SegmentBuilder},
};
use alloc::{boxed::Box, vec::Vec};
use core::ptr::NonNull;
use hashbrown::{HashMap, HashSet, hash_map::Entry};

/// Convert section flags to memory protection flags
pub(crate) fn section_prot(sh_flags: ElfSectionFlags) -> ProtFlags {
    let mut prot = ProtFlags::PROT_READ;
    if sh_flags.contains(ElfSectionFlags::WRITE) {
        prot |= ProtFlags::PROT_WRITE;
    }
    if sh_flags.contains(ElfSectionFlags::EXECINSTR) {
        prot |= ProtFlags::PROT_EXEC;
    }
    prot
}

/// Manages segments created from ELF section headers
pub(crate) struct SectionSegments<Arch: ObjectRelocationArch = crate::arch::NativeArch> {
    core: SectionSegmentSet,
    init: SectionSegmentSet,
    section_lifetimes: Box<[SectionLifetime]>,
    pltgot_lifetimes: PltGotLifetimes,
    pltgot: Option<PltGotSection>,
    _arch: core::marker::PhantomData<Arch>,
}

pub(crate) struct ObjectSegments<R: RegionAccess> {
    core: ElfSegments<R>,
    init: Option<ElfSegments<R>>,
}

impl<R: RegionAccess> ObjectSegments<R> {
    #[inline]
    pub(crate) const fn new(core: ElfSegments<R>, init: Option<ElfSegments<R>>) -> Self {
        Self { core, init }
    }

    #[inline]
    pub(crate) fn init(&self) -> Option<&ElfSegments<R>> {
        self.init.as_ref()
    }

    #[inline]
    pub(crate) fn view(&self) -> ObjectSegmentView<'_, R> {
        ObjectSegmentView::new(&self.core, self.init.as_ref())
    }

    #[inline]
    pub(crate) fn base_for(&self, lifetime: SectionLifetime) -> VmAddr {
        match lifetime {
            SectionLifetime::Core => self.core.base(),
            SectionLifetime::Init => self
                .init()
                .map(ElfSegments::base)
                .unwrap_or_else(|| self.core.base()),
        }
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (ElfSegments<R>, Option<ElfSegments<R>>) {
        (self.core, self.init)
    }
}

pub(crate) struct ObjectSegmentView<'segments, R: RegionAccess> {
    core: &'segments ElfSegments<R>,
    init: Option<&'segments ElfSegments<R>>,
}

impl<R: RegionAccess> Clone for ObjectSegmentView<'_, R> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: RegionAccess> Copy for ObjectSegmentView<'_, R> {}

impl<'segments, R: RegionAccess> ObjectSegmentView<'segments, R> {
    #[inline]
    pub(crate) const fn new(
        core: &'segments ElfSegments<R>,
        init: Option<&'segments ElfSegments<R>>,
    ) -> Self {
        Self { core, init }
    }

    #[inline]
    pub(crate) const fn core(&self) -> &'segments ElfSegments<R> {
        self.core
    }

    #[inline]
    pub(crate) const fn init(&self) -> Option<&'segments ElfSegments<R>> {
        self.init
    }

    #[inline]
    fn segment_for_addr(&self, addr: VmAddr) -> Result<&'segments ElfSegments<R>> {
        if self.core.contains_addr(addr) {
            return Ok(self.core);
        }
        if let Some(init) = self.init
            && init.contains_addr(addr)
        {
            return Ok(init);
        }
        Err(MmapError::InvalidMappedRegionRange.into())
    }
}

impl<R: RegionAccess> ImageMemory for ObjectSegmentView<'_, R> {
    #[inline]
    fn base(&self) -> VmAddr {
        self.core.base()
    }

    #[inline]
    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        self.host_ptr_range(addr, 1)
    }

    #[inline]
    fn host_ptr_range(&self, addr: VmAddr, len: usize) -> Option<NonNull<u8>> {
        if self.core.contains_range(addr, len) {
            return self.core.host_ptr_range(addr, len);
        }
        if let Some(init) = self.init
            && init.contains_range(addr, len)
        {
            return init.host_ptr_range(addr, len);
        }
        None
    }

    #[inline]
    fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        self.segment_for_addr(addr)?.read_bytes(addr, dst)
    }

    #[inline]
    fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> Result<()> {
        self.segment_for_addr(addr)?.write_bytes(addr, src)
    }
}

/// User-defined bucket used to place object sections during layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SectionGroup(u16);

impl SectionGroup {
    /// Creates a section layout group identifier.
    #[inline]
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the raw group identifier.
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Lifetime class for sections placed in a runtime layout group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SectionLifetime {
    /// Section memory is retained for the object lifetime.
    Core,
    /// Section memory may be released after initialization completes.
    Init,
}

#[derive(Clone, Copy)]
pub(crate) struct SectionGroupDef {
    pub(crate) group: SectionGroup,
    pub(crate) prot: ProtFlags,
    pub(crate) order: usize,
    pub(crate) lifetime: SectionLifetime,
}

impl SectionGroupDef {
    #[inline]
    pub(crate) const fn new(
        group: SectionGroup,
        prot: ProtFlags,
        order: usize,
        lifetime: SectionLifetime,
    ) -> Self {
        Self {
            group,
            prot,
            order,
            lifetime,
        }
    }
}

#[derive(Default)]
pub(crate) struct SectionGroups {
    defs: Vec<SectionGroupDef>,
}

impl SectionGroups {
    #[inline]
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            defs: Vec::with_capacity(capacity),
        }
    }

    fn default_layout() -> Self {
        let mut groups = Self::with_capacity(4);
        groups.define(
            SectionGroup::new(0),
            ProtFlags::PROT_READ,
            0,
            SectionLifetime::Core,
        );
        groups.define(
            SectionGroup::new(1),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            1,
            SectionLifetime::Core,
        );
        groups.define(
            SectionGroup::new(2),
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            2,
            SectionLifetime::Core,
        );
        groups.define(
            SectionGroup::new(3),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
            3,
            SectionLifetime::Core,
        );
        groups
    }

    #[inline]
    pub(crate) fn define(
        &mut self,
        group: SectionGroup,
        prot: ProtFlags,
        order: usize,
        lifetime: SectionLifetime,
    ) {
        self.upsert(SectionGroupDef::new(group, prot, order, lifetime));
    }

    pub(crate) fn upsert(&mut self, new_group: SectionGroupDef) {
        if let Some(group) = self
            .defs
            .iter_mut()
            .find(|group| group.group == new_group.group)
        {
            *group = new_group;
        } else {
            self.defs.push(new_group);
        }
    }

    pub(crate) fn merge(&mut self, overrides: Self) {
        for group in overrides.defs {
            self.upsert(group);
        }
    }

    pub(crate) fn sorted_defs(&self) -> Vec<SectionGroupDef> {
        let mut defs = self.defs.clone();
        defs.sort_by_key(|def| {
            (
                def.order,
                matches!(def.lifetime, SectionLifetime::Init),
                def.group.get(),
            )
        });
        defs
    }

    #[inline]
    pub(crate) fn def(&self, group: SectionGroup) -> Option<SectionGroupDef> {
        self.defs.iter().copied().find(|def| def.group == group)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum SectionPlacement {
    Place(SectionGroup),
    Stage,
    Skip,
}

/// Final object section layout choices collected from [`SectionLayoutEvent`].
pub(crate) struct SectionLayoutPlan {
    groups: SectionGroups,
    placements: Vec<SectionPlacement>,
}

impl SectionLayoutPlan {
    #[inline]
    pub(crate) fn new(groups: SectionGroups, placements: Vec<SectionPlacement>) -> Self {
        Self { groups, placements }
    }

    #[inline]
    pub(crate) fn groups(&self) -> &SectionGroups {
        &self.groups
    }

    #[inline]
    pub(crate) fn placement(&self, id: ElfSectionId) -> SectionPlacement {
        self.placements[id.index()]
    }

    #[inline]
    pub(crate) fn group_def(&self, group: SectionGroup) -> Option<SectionGroupDef> {
        self.groups.def(group)
    }
}

fn prot_to_idx(prot: ProtFlags) -> usize {
    usize::from(prot.contains(ProtFlags::PROT_WRITE))
        | (usize::from(prot.contains(ProtFlags::PROT_EXEC)) << 1)
}

fn flags_to_idx(flags: ElfSectionFlags) -> usize {
    prot_to_idx(section_prot(flags))
}

fn default_section_group(flags: ElfSectionFlags) -> SectionGroup {
    SectionGroup::new(flags_to_idx(flags) as u16)
}

fn create_section_plan<L: ElfLayout>(
    sections: &ObjectSections<L>,
    group_overrides: SectionGroups,
    placement_overrides: Vec<Option<SectionPlacement>>,
) -> SectionLayoutPlan {
    debug_assert_eq!(sections.headers().len(), placement_overrides.len());

    let mut groups = SectionGroups::default_layout();
    groups.merge(group_overrides);

    let placements = sections
        .headers()
        .iter()
        .enumerate()
        .map(|(index, shdr)| {
            placement_overrides[index].unwrap_or_else(|| {
                if shdr.flags().contains(ElfSectionFlags::ALLOC) {
                    SectionPlacement::Place(default_section_group(shdr.flags()))
                } else {
                    SectionPlacement::Stage
                }
            })
        })
        .collect();
    SectionLayoutPlan::new(groups, placements)
}

enum PltGotShdr<L: ElfLayout> {
    Existing(ElfSectionId),
    Synthetic(ElfShdr<L>),
}

impl<L: ElfLayout> PltGotShdr<L> {
    #[inline]
    fn new(existing: Option<ElfSectionId>, synthetic: impl FnOnce() -> ElfShdr<L>) -> Self {
        match existing {
            Some(id) => Self::Existing(id),
            None => Self::Synthetic(synthetic()),
        }
    }

    #[inline]
    fn addr(&self, sections: &ObjectSections<L>) -> VmAddr {
        let addr = match self {
            Self::Existing(id) => sections.section(*id).sh_addr(),
            Self::Synthetic(shdr) => shdr.sh_addr(),
        };
        VmAddr::new(addr)
    }
}

struct PltGotShdrs<L: ElfLayout> {
    got: PltGotShdr<L>,
    got_plt: PltGotShdr<L>,
    plt: PltGotShdr<L>,
}

#[derive(Clone, Copy)]
struct PltGotLifetimes {
    got: SectionLifetime,
    got_plt: SectionLifetime,
    plt: SectionLifetime,
}

impl Default for PltGotLifetimes {
    #[inline]
    fn default() -> Self {
        Self {
            got: SectionLifetime::Core,
            got_plt: SectionLifetime::Core,
            plt: SectionLifetime::Core,
        }
    }
}

impl<L: ElfLayout> PltGotShdr<L> {
    #[inline]
    fn lifetime(&self, section_lifetimes: &[SectionLifetime]) -> SectionLifetime {
        match self {
            Self::Existing(id) => section_lifetimes[id.index()],
            Self::Synthetic(_) => SectionLifetime::Core,
        }
    }
}

fn prepare_pltgot_shdrs<L: ElfLayout>(
    sections: &mut ObjectSections<L>,
    got_cnt: usize,
    plt_cnt: usize,
) -> PltGotShdrs<L> {
    let mut got = None;
    let mut got_plt = None;
    let mut plt = None;
    for index in 0..sections.headers().len() {
        let id = ElfSectionId::new(index);
        match sections.section_name(id).to_bytes() {
            b".got" => got = Some(id),
            b".got.plt" => got_plt = Some(id),
            b".plt" => plt = Some(id),
            _ => {}
        }
    }

    if let Some(id) = got {
        configure_pltgot_shdr(
            &mut sections.headers_mut()[id.index()],
            ElfSectionFlags::ALLOC | ElfSectionFlags::WRITE,
            got_cnt,
            size_of::<usize>(),
        );
    }
    if let Some(id) = got_plt {
        configure_pltgot_shdr(
            &mut sections.headers_mut()[id.index()],
            ElfSectionFlags::ALLOC | ElfSectionFlags::WRITE,
            plt_cnt,
            size_of::<usize>(),
        );
    }
    if let Some(id) = plt {
        configure_pltgot_shdr(
            &mut sections.headers_mut()[id.index()],
            ElfSectionFlags::ALLOC | ElfSectionFlags::EXECINSTR,
            plt_cnt,
            PLT_ENTRY_SIZE,
        );
        sections.headers_mut()[id.index()].set_sh_addralign(size_of::<usize>());
    }

    PltGotShdrs {
        got: PltGotShdr::new(got, || PltGotSection::create_got_shdr(got_cnt)),
        got_plt: PltGotShdr::new(got_plt, || PltGotSection::create_got_plt_shdr(plt_cnt)),
        plt: PltGotShdr::new(plt, || PltGotSection::create_plt_shdr(plt_cnt)),
    }
}

fn configure_pltgot_shdr<L: ElfLayout>(
    shdr: &mut ElfShdr<L>,
    flags: ElfSectionFlags,
    elem_cnt: usize,
    ent_size: usize,
) {
    shdr.set_section_type(ElfSectionType::NOBITS);
    shdr.set_flags(flags);
    shdr.set_sh_size(elem_cnt * ent_size);
    shdr.set_sh_addralign(16);
    shdr.set_sh_entsize(ent_size);
}

fn create_pltgot_shdr<L: ElfLayout>(
    flags: ElfSectionFlags,
    elem_cnt: usize,
    ent_size: usize,
) -> ElfShdr<L> {
    ElfShdr::new(
        0,
        ElfSectionType::NOBITS,
        flags,
        0,
        0,
        elem_cnt * ent_size,
        0,
        0,
        16,
        ent_size,
    )
}

#[derive(Default)]
struct SectionSegmentSet {
    segments: Vec<ElfSegment>,
    total_size: usize,
}

impl SectionSegmentSet {
    #[inline]
    fn is_empty(&self) -> bool {
        self.total_size == 0
    }

    #[inline]
    fn push(&mut self, segment: ElfSegment) {
        self.segments.push(segment);
    }
}

impl SegmentBuilder for SectionSegmentSet {
    fn create_space<M>(&mut self, mapper: &M) -> Result<ElfSegments<M::Region>>
    where
        M: Mmap + ?Sized,
    {
        let len = self.total_size;
        let region = unsafe {
            mapper.create_space(
                None,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                false,
            )
        }?;
        let base = region.addr();
        Ok(ElfSegments::new(region, base, VmOffset::new(0)))
    }

    fn create_segments(&mut self) -> Result<()> {
        Ok(())
    }

    fn segments_mut(&mut self) -> &mut [ElfSegment] {
        &mut self.segments
    }

    fn segments(&self) -> &[ElfSegment] {
        &self.segments
    }
}

impl<Arch: ObjectRelocationArch> SectionSegments<Arch> {
    pub(crate) fn new<D, Obs>(
        sections: &mut ObjectSections<Arch::Layout>,
        object: &impl ElfReader,
        page_size: usize,
        observer: &mut Obs,
    ) -> Result<Self>
    where
        D: 'static,
        Obs: LoadObserver<D, Arch>,
    {
        let (got_cnt, plt_cnt) =
            PltGotSection::count_needed_entries::<Arch>(sections.headers(), object)?;

        let mut pltgot_shdrs = prepare_pltgot_shdrs(sections, got_cnt, plt_cnt);
        let mut event = SectionLayoutEvent::new(sections);
        observer.on_section_layout(&mut event)?;
        let (group_overrides, placement_overrides) = event.into_overrides();
        let plan = create_section_plan(sections, group_overrides, placement_overrides);
        let mut units = create_section_units::<Arch::Layout>(&plan);
        let mut staged = SectionUnit::new(
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            SectionLifetime::Core,
        );
        let mut section_lifetimes =
            alloc::vec![SectionLifetime::Core; sections.headers().len()].into_boxed_slice();

        for (index, shdr) in sections.headers_mut().iter_mut().enumerate() {
            let id = ElfSectionId::new(index);
            match plan.placement(ElfSectionId::new(index)) {
                SectionPlacement::Place(group) => {
                    let group_def = plan.group_def(group).ok_or_else(|| {
                        ParseShdrError::malformed("section layout group is not defined")
                    })?;
                    section_lifetimes[id.index()] = group_def.lifetime;
                    add_section_to_units(&mut units, group, shdr)?
                }
                SectionPlacement::Stage => {
                    section_lifetimes[id.index()] = SectionLifetime::Core;
                    staged.add_section(shdr);
                }
                SectionPlacement::Skip => {}
            }
        }
        if let PltGotShdr::Synthetic(shdr) = &mut pltgot_shdrs.got {
            add_section_to_units(&mut units, default_section_group(shdr.flags()), shdr)?;
        }
        if let PltGotShdr::Synthetic(shdr) = &mut pltgot_shdrs.got_plt {
            add_section_to_units(&mut units, default_section_group(shdr.flags()), shdr)?;
        }
        if let PltGotShdr::Synthetic(shdr) = &mut pltgot_shdrs.plt {
            add_section_to_units(&mut units, default_section_group(shdr.flags()), shdr)?;
        }

        let mut core = SectionSegmentSet::default();
        let mut init = SectionSegmentSet::default();
        let mut core_offset = 0;
        let mut init_offset = 0;
        for (_, unit) in &mut units {
            let (offset, segment_set) = match unit.lifetime {
                SectionLifetime::Core => (&mut core_offset, &mut core),
                SectionLifetime::Init => (&mut init_offset, &mut init),
            };
            if let Some((segment, _)) = unit.create_segment(offset, page_size) {
                *offset = roundup(*offset, page_size);
                segment_set.push(segment);
            }
        }
        if let Some((segment, _)) = staged.create_segment(&mut core_offset, page_size) {
            core_offset = roundup(core_offset, page_size);
            core.push(segment);
        }
        drop(units);
        drop(staged);
        core.total_size = core_offset;
        init.total_size = init_offset;

        let got_base = pltgot_shdrs.got.addr(sections);
        let got_plt_base = pltgot_shdrs.got_plt.addr(sections);
        let plt_base = pltgot_shdrs.plt.addr(sections);
        let pltgot_lifetimes = PltGotLifetimes {
            got: pltgot_shdrs.got.lifetime(&section_lifetimes),
            got_plt: pltgot_shdrs.got_plt.lifetime(&section_lifetimes),
            plt: pltgot_shdrs.plt.lifetime(&section_lifetimes),
        };

        Ok(Self {
            core,
            init,
            section_lifetimes,
            pltgot_lifetimes,
            pltgot: Some(PltGotSection::new(got_base, got_plt_base, plt_base)),
            _arch: core::marker::PhantomData,
        })
    }

    pub(crate) fn take_pltgot(&mut self) -> PltGotSection {
        self.pltgot.take().expect("PLTGOT already taken")
    }

    pub(crate) fn load_segments<M>(
        &mut self,
        mapper: &M,
        object: &impl ElfReader,
    ) -> Result<ObjectSegments<M::Region>>
    where
        M: Mmap + ?Sized,
    {
        let core = self.core.load_segments(mapper, object)?;
        let init = if self.init.is_empty() {
            None
        } else {
            Some(self.init.load_segments(mapper, object)?)
        };
        Ok(ObjectSegments::new(core, init))
    }

    pub(crate) fn mprotect<R>(&self, segments: &ObjectSegmentView<'_, R>) -> Result<()>
    where
        R: RegionAccess,
    {
        self.core.mprotect(segments.core())?;
        if let Some(init) = segments.init() {
            self.init.mprotect(init)?;
        }
        Ok(())
    }

    pub(crate) fn rebase_loaded_sections<R>(
        &mut self,
        shdrs: &mut [ElfShdr<Arch::Layout>],
        segments: &ObjectSegments<R>,
    ) where
        R: RegionAccess,
    {
        for (index, shdr) in shdrs.iter_mut().enumerate() {
            let base = segments.base_for(self.section_lifetimes[index]);
            shdr.set_sh_addr((base + VmOffset::new(shdr.sh_addr())).get());
        }

        if let Some(pltgot) = &mut self.pltgot {
            pltgot.rebase_to(
                segments.base_for(self.pltgot_lifetimes.got),
                segments.base_for(self.pltgot_lifetimes.got_plt),
                segments.base_for(self.pltgot_lifetimes.plt),
            );
        }
    }
}

/// Manages PLT (Procedure Linkage Table) and GOT (Global Offset Table) sections
pub(crate) struct PltGotSection {
    got_base: VmAddr,
    got_plt_base: VmAddr,
    plt_base: VmAddr,
    got_idx: usize,
    got_plt_idx: usize,
    plt_idx: usize,
    got_map: HashMap<ObjectRelocKey, usize>,
    plt_map: HashMap<ObjectRelocKey, usize>,
}

pub(crate) struct UsizeEntry<'entry>(&'entry mut usize);

impl UsizeEntry<'_> {
    pub(crate) fn update(&mut self, value: VmAddr) {
        *self.0 = value.get();
    }

    pub(crate) fn get_addr(&self) -> VmAddr {
        VmAddr::from_ptr(self.0 as *const _)
    }
}

pub(crate) enum GotEntry<'got> {
    Occupied(VmAddr),
    Vacant(UsizeEntry<'got>),
}

pub(crate) enum PltEntry<'plt> {
    Occupied(VmAddr),
    Vacant {
        plt: &'plt mut [u8],
        got: UsizeEntry<'plt>,
    },
}

/// Relocation identity used to deduplicate object GOT/PLT entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ObjectRelocKey {
    r_type: crate::elf::ElfRelocationType,
    r_sym: usize,
    addend: isize,
}

impl ObjectRelocKey {
    #[inline]
    pub(crate) fn new<Arch: RelocationArch>(rel: &ElfRelType<Arch>) -> Self {
        let addend = if <ElfRelType<Arch> as ElfRelEntry<Arch::Layout>>::HAS_IMPLICIT_ADDEND {
            0
        } else {
            rel.r_addend(VmAddr::null())
        };
        Self {
            r_type: rel.r_type(),
            r_sym: rel.r_symbol(),
            addend,
        }
    }
}

impl PltGotSection {
    fn count_needed_entries<Arch: ObjectRelocationArch>(
        shdrs: &[ElfShdr<Arch::Layout>],
        object: &impl ElfReader,
    ) -> Result<(usize, usize)> {
        let mut got_set = HashSet::new();
        let mut got_plt_set = HashSet::new();
        let mut scratch =
            AlignedBytes::with_len(0).expect("failed to initialize relocation buffer");

        for shdr in shdrs
            .iter()
            .filter(|s| matches!(s.section_type(), ElfSectionType::REL | ElfSectionType::RELA))
        {
            let entry_size = size_of::<ElfRelType<Arch>>();
            let size = shdr.sh_size() / entry_size * entry_size;
            if size == 0 {
                continue;
            }

            object.with_bytes::<ElfRelType<Arch>, _, _>(
                shdr.sh_offset(),
                size,
                &mut scratch,
                |relocations| {
                    for rel_entry in relocations {
                        let r_type = rel_entry.r_type();
                        let key = ObjectRelocKey::new::<Arch>(rel_entry);

                        if Arch::object_needs_got(r_type) {
                            got_set.insert(key);
                        }
                        if Arch::object_needs_plt(r_type) {
                            got_plt_set.insert(key);
                        }
                    }
                    Ok(())
                },
            )?;
        }

        Ok((got_set.len(), got_plt_set.len()))
    }

    fn create_got_shdr<L: ElfLayout>(elem_cnt: usize) -> ElfShdr<L> {
        create_pltgot_shdr(
            ElfSectionFlags::ALLOC | ElfSectionFlags::WRITE,
            elem_cnt,
            size_of::<usize>(),
        )
    }

    fn create_got_plt_shdr<L: ElfLayout>(elem_cnt: usize) -> ElfShdr<L> {
        create_pltgot_shdr(
            ElfSectionFlags::ALLOC | ElfSectionFlags::WRITE,
            elem_cnt,
            size_of::<usize>(),
        )
    }

    fn create_plt_shdr<L: ElfLayout>(elem_cnt: usize) -> ElfShdr<L> {
        let mut shdr = create_pltgot_shdr(
            ElfSectionFlags::ALLOC | ElfSectionFlags::EXECINSTR,
            elem_cnt,
            PLT_ENTRY_SIZE,
        );
        shdr.set_sh_addralign(size_of::<usize>());
        shdr
    }

    fn new(got_base: VmAddr, got_plt_base: VmAddr, plt_base: VmAddr) -> Self {
        Self {
            got_idx: 0,
            got_plt_idx: 0,
            plt_idx: 0,
            got_map: HashMap::new(),
            plt_map: HashMap::new(),
            got_base,
            got_plt_base,
            plt_base,
        }
    }

    pub(crate) fn rebase_to(&mut self, got_base: VmAddr, got_plt_base: VmAddr, plt_base: VmAddr) {
        self.got_base = got_base + VmOffset::new(self.got_base.get());
        self.got_plt_base = got_plt_base + VmOffset::new(self.got_plt_base.get());
        self.plt_base = plt_base + VmOffset::new(self.plt_base.get());
    }

    pub(crate) fn add_got_entry(&mut self, key: ObjectRelocKey) -> GotEntry<'_> {
        let base = self.got_base;
        let ent_size = size_of::<usize>();
        match self.got_map.entry(key) {
            Entry::Occupied(mut entry) => {
                GotEntry::Occupied(base + VmOffset::new(*entry.get_mut() * ent_size))
            }
            Entry::Vacant(entry) => {
                let idx = *entry.insert(self.got_idx);
                self.got_idx += 1;
                GotEntry::Vacant(unsafe {
                    UsizeEntry(&mut *(base + VmOffset::new(idx * ent_size)).as_mut_ptr())
                })
            }
        }
    }

    pub(crate) fn add_plt_entry(&mut self, key: ObjectRelocKey) -> PltEntry<'_> {
        let plt_base = self.plt_base;
        let got_plt_base = self.got_plt_base;
        let plt_ent_size = PLT_ENTRY_SIZE;
        let got_ent_size = size_of::<usize>();
        match self.plt_map.entry(key) {
            Entry::Occupied(mut entry) => {
                PltEntry::Occupied(plt_base + VmOffset::new(*entry.get_mut() * plt_ent_size))
            }
            Entry::Vacant(entry) => {
                let plt_idx = *entry.insert(self.plt_idx);
                self.plt_idx += 1;

                let got_idx = self.got_plt_idx;
                self.got_plt_idx += 1;

                let plt = unsafe {
                    core::slice::from_raw_parts_mut(
                        (plt_base + VmOffset::new(plt_idx * plt_ent_size)).as_mut_ptr(),
                        plt_ent_size,
                    )
                };

                plt.copy_from_slice(&PLT_ENTRY);

                PltEntry::Vacant {
                    plt,
                    got: unsafe {
                        UsizeEntry(
                            &mut *(got_plt_base + VmOffset::new(got_idx * got_ent_size))
                                .as_mut_ptr(),
                        )
                    },
                }
            }
        }
    }
}

struct SectionUnit<'shdr, L: ElfLayout> {
    prot: ProtFlags,
    lifetime: SectionLifetime,
    content_sections: Vec<&'shdr mut ElfShdr<L>>,
    zero_sections: Vec<&'shdr mut ElfShdr<L>>,
}

impl<'shdr, L: ElfLayout> SectionUnit<'shdr, L> {
    fn new(prot: ProtFlags, lifetime: SectionLifetime) -> Self {
        Self {
            prot,
            lifetime,
            content_sections: Vec::new(),
            zero_sections: Vec::new(),
        }
    }

    fn add_section(&mut self, shdr: &'shdr mut ElfShdr<L>) {
        if shdr.section_type() == ElfSectionType::NOBITS {
            self.zero_sections.push(shdr);
        } else {
            self.content_sections.push(shdr);
        }
    }

    fn create_segment(
        &mut self,
        base_offset: &mut usize,
        page_size: usize,
    ) -> Option<(ElfSegment, SectionLifetime)> {
        self.content_sections
            .first()
            .or(self.zero_sections.first())?;

        let segment_start = *base_offset;

        let mut current_offset = segment_start;
        let mut map_info = Vec::new();
        for shdr in &mut self.content_sections {
            if shdr.sh_size() == 0 {
                continue;
            }
            current_offset = roundup(current_offset, shdr.sh_addralign());
            shdr.set_sh_addr(current_offset);
            map_info.push(FileMapInfo {
                filesz: shdr.sh_size(),
                offset: shdr.sh_offset(),
                start: current_offset - segment_start,
            });
            current_offset += shdr.sh_size();
        }

        if map_info.len() == 1 {
            let info = &mut map_info[0];
            let file_offset = rounddown(info.offset, page_size);
            let align_len = info.offset - file_offset;

            let shdr = self
                .content_sections
                .iter_mut()
                .find(|shdr| shdr.sh_offset() == info.offset)
                .unwrap();

            shdr.add_sh_addr(align_len);
            info.filesz += align_len;
            info.offset = file_offset;
            current_offset += align_len;
        }

        let content_size = current_offset - segment_start;

        for shdr in &mut self.zero_sections {
            current_offset = roundup(current_offset, shdr.sh_addralign());
            shdr.set_sh_addr(current_offset);
            current_offset += shdr.sh_size();
        }

        let unaligned_total_size = current_offset - segment_start;
        let total_size = roundup(unaligned_total_size, page_size);

        if total_size == 0 {
            return None;
        }

        *base_offset += total_size;
        Some((
            ElfSegment {
                offset: VmOffset::new(segment_start),
                prot: self.prot,
                len: total_size,
                page_size,
                content_size,
                zero_size: unaligned_total_size - content_size,
                need_copy: false,
                flags: MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                map_info,
                from_relocatable: true,
            },
            self.lifetime,
        ))
    }
}

fn create_section_units<L: ElfLayout>(
    plan: &SectionLayoutPlan,
) -> Vec<(SectionGroup, SectionUnit<'_, L>)> {
    plan.groups()
        .sorted_defs()
        .into_iter()
        .map(|def| (def.group, SectionUnit::new(def.prot, def.lifetime)))
        .collect()
}

fn add_section_to_units<'shdr, L: ElfLayout>(
    units: &mut [(SectionGroup, SectionUnit<'shdr, L>)],
    group: SectionGroup,
    shdr: &'shdr mut ElfShdr<L>,
) -> Result<()> {
    let Some((_, unit)) = units
        .iter_mut()
        .find(|(unit_group, _)| *unit_group == group)
    else {
        return Err(ParseShdrError::malformed("section layout group is not defined").into());
    };
    unit.add_section(shdr);
    Ok(())
}
