//! Relocation of elf objects
use crate::{
    ParseDynamicError, RelocReason, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfRelr, ElfWord},
    image::{LoadedCore, RawDynamic},
    logging,
    relocation::{
        BindingMode, RelocHelper, RelocValue, RelocateArgs, RelocationArch, RelocationHandler,
        ResolvedBinding, likely, reloc_error, resolve_ifunc, unlikely,
    },
    tls::{TlsRelocOutcome, handle_tls_reloc},
};
use core::num::NonZeroUsize;

impl<D, Arch: RelocationArch> RawDynamic<D, Arch> {
    fn apply_relro(&self, binding: &ResolvedBinding) -> Result<()> {
        if binding.is_lazy() {
            return Ok(());
        }

        if let Some(relro) = self.relro() {
            relro.relro()?;
        }
        Ok(())
    }

    pub(crate) fn relocate_impl<PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, Arch, PreH, PostH>,
    ) -> Result<LoadedCore<D, Arch>>
    where
        D: 'static,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        logging::info!("Relocating dynamic library: {}", self.name());

        let RelocateArgs {
            scope,
            binding,
            pre_handler,
            post_handler,
            emu,
            ..
        } = args;

        let relocation = self.relocation();
        if relocation.is_empty() {
            logging::debug!("No relocations needed for {}", self.name());
        }

        let binding = self.resolve_binding(if Arch::SUPPORTS_NATIVE_RUNTIME {
            binding
        } else {
            BindingMode::Eager
        });
        let tls_get_addr = self.tls_get_addr();

        if binding.is_lazy() {
            logging::debug!("Using lazy binding for {}", self.name());
        }

        let mut helper = RelocHelper::new(
            self.core_ref(),
            scope,
            pre_handler,
            post_handler,
            tls_get_addr,
            emu.clone(),
        );

        if !relocation.is_empty() {
            self.relocate_relative()
                .relocate_dynrel(&mut helper)?
                .relocate_pltrel(&binding, &mut helper)?;
        }

        let RelocHelper {
            scope,
            tls_desc_args,
            ..
        } = helper;
        // Persist TLSDESC backing storage collected during relocation.
        unsafe {
            self.core_ref().set_tls_desc_args(tls_desc_args);
        }

        let dep_names = scope
            .iter()
            .filter_map(|source| source.as_any().downcast_ref::<LoadedCore<D, Arch>>())
            .map(|d| d.name())
            .collect::<alloc::vec::Vec<_>>();
        if !dep_names.is_empty() {
            logging::debug!("[{}] Bound dependencies: {:?}", self.name(), dep_names);
        }

        self.apply_relro(&binding)?;
        self.install_lazy_lookup(binding, scope.clone())?;

        if Arch::SUPPORTS_NATIVE_RUNTIME {
            logging::debug!("Executing initialization functions for {}", self.name());
            self.call_init();
        } else if let Some(emu) = emu {
            logging::debug!(
                "Executing initialization functions with emulator for {}",
                self.name()
            );
            self.call_init_with_emu(emu)?;
        } else {
            logging::debug!(
                "Skipping initialization functions for non-native relocation of {}",
                self.name()
            );
        }

        logging::info!("Relocation completed for {}", self.name());

        Ok(unsafe { LoadedCore::from_core_deps(self.into_core(), scope) })
    }
}

/// Types of relative relocations
enum RelativeRel<Arch: RelocationArch> {
    /// Standard REL/RELA relocations
    Rel(&'static [ElfRelType<Arch>]),
    /// Compact RELR relocations
    Relr(&'static [ElfRelr<Arch::Layout>]),
}

impl<Arch: RelocationArch> RelativeRel<Arch> {
    #[inline]
    fn is_empty(&self) -> bool {
        match self {
            RelativeRel::Rel(rel) => rel.is_empty(),
            RelativeRel::Relr(relr) => relr.is_empty(),
        }
    }
}

/// Holds parsed relocation information
pub(crate) struct DynamicRelocation<Arch: RelocationArch = crate::arch::NativeArch> {
    /// Relative relocations (REL_RELATIVE)
    relative: RelativeRel<Arch>,
    /// PLT relocations
    pub(in crate::relocation) pltrel: &'static [ElfRelType<Arch>],
    /// Other dynamic relocations
    dynrel: &'static [ElfRelType<Arch>],
}

#[inline]
fn write_reloc_addr<Arch: RelocationArch>(
    segments: &crate::segment::ElfSegments,
    r_offset: usize,
    value: crate::relocation::RelocAddr,
) {
    segments.write(
        r_offset,
        RelocValue::new(<Arch::Layout as ElfLayout>::Word::from_usize(
            value.into_inner(),
        )),
    );
}

impl<D, Arch: RelocationArch> RawDynamic<D, Arch> {
    /// Relocate PLT (Procedure Linkage Table) entries
    fn relocate_pltrel<PreH, PostH>(
        &self,
        binding: &ResolvedBinding,
        helper: &mut RelocHelper<'_, D, Arch, PreH, PostH>,
    ) -> Result<&Self>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        let core = self.core_ref();
        let base = core.base_addr();
        let segments = core.segments();
        let reloc = self.relocation();
        debug_assert!(Arch::SUPPORTS_NATIVE_RUNTIME || !binding.is_lazy());
        binding.prepare_plt(self)?;

        // Process PLT relocations
        for rel in reloc.pltrel {
            if !helper.handle_pre(rel)?.is_unhandled() {
                continue;
            }
            let r_type = rel.r_type();
            let r_sym = rel.r_symbol();
            let mut failure_reason = RelocReason::Unsupported;

            // Handle jump slot relocations
            if likely(r_type == Arch::JUMP_SLOT) {
                if binding.relocate_jump_slot::<Arch>(base, rel) {
                    continue;
                }

                if let Some(symbol) = helper.find_symbol(r_sym) {
                    write_reloc_addr::<Arch>(segments, rel.r_offset(), symbol);
                    continue;
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if unlikely(r_type == Arch::IRELATIVE) {
                let r_addend = rel.r_addend(base.into_inner());
                let addr = base.addend(r_addend);
                if !Arch::SUPPORTS_NATIVE_RUNTIME {
                    if let Some(resolved) = helper.resolve_ifunc_with_emu(rel, addr)? {
                        write_reloc_addr::<Arch>(segments, rel.r_offset(), resolved);
                        continue;
                    }
                    failure_reason = RelocReason::MissingEmulator;
                } else {
                    write_reloc_addr::<Arch>(segments, rel.r_offset(), unsafe {
                        resolve_ifunc(addr)
                    });
                    continue;
                }
            } else if unlikely(Arch::is_tlsdesc(r_type)) {
                // `handle_tls_reloc` performs its own SUPPORTS_NATIVE_RUNTIME
                // gate for TLSDESC. If the built-in path cannot handle it,
                // keep the specific TLS failure for the final error while
                // still giving the post handler a chance.
                match handle_tls_reloc::<_, Arch, _, _>(helper, rel)? {
                    TlsRelocOutcome::Applied => continue,
                    TlsRelocOutcome::Failed(reason) => failure_reason = reason,
                }
            }
            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel)?.is_unhandled() {
                return Err(reloc_error::<Arch, _>(rel, failure_reason, core));
            }
        }
        Ok(self)
    }

    /// Perform relative relocations (REL_RELATIVE)
    fn relocate_relative(&self) -> &Self {
        let core = self.core_ref();
        let reloc = self.relocation();
        let segments = core.segments();
        let base = core.base_addr();

        match reloc.relative {
            RelativeRel::Rel(rel) => {
                assert!(rel.is_empty() || rel[0].r_type() == Arch::RELATIVE);
                // Apply all relative relocations: new_value = base_address + addend
                for rel in rel {
                    debug_assert!(rel.r_type() == Arch::RELATIVE);
                    let r_addend = rel.r_addend(base.into_inner());
                    write_reloc_addr::<Arch>(segments, rel.r_offset(), base.addend(r_addend));
                }
            }
            RelativeRel::Relr(relr) => {
                // Apply compact relative relocations (RELR format)
                let mut reloc_addr = core::ptr::null_mut::<<Arch::Layout as ElfLayout>::Word>();

                for relr in relr {
                    let value = relr.value();

                    unsafe {
                        if (value & 1) == 0 {
                            reloc_addr =
                                segments.get_mut_ptr::<<Arch::Layout as ElfLayout>::Word>(value);
                            reloc_addr.write(<Arch::Layout as ElfLayout>::Word::from_usize(
                                base.offset(reloc_addr.read().to_usize()).into_inner(),
                            ));
                            reloc_addr = reloc_addr.add(1);
                            continue;
                        }

                        let mut bitmap = value >> 1;
                        let mut ptr = reloc_addr;
                        while bitmap != 0 {
                            if (bitmap & 1) != 0 {
                                ptr.write(<Arch::Layout as ElfLayout>::Word::from_usize(
                                    base.offset(ptr.read().to_usize()).into_inner(),
                                ));
                            }
                            bitmap >>= 1;
                            ptr = ptr.add(1);
                        }
                        reloc_addr = reloc_addr.add(<Arch::Layout as ElfLayout>::Word::BITS - 1);
                    }
                }
            }
        }
        self
    }

    /// Perform dynamic relocations (non-PLT, non-relative)
    fn relocate_dynrel<PreH, PostH>(
        &self,
        helper: &mut RelocHelper<'_, D, Arch, PreH, PostH>,
    ) -> Result<&Self>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        /*
            Relocation formula components:
            A = Addend used to compute the value of the relocatable field
            B = Base address at which a shared object is loaded
            S = Value of the symbol whose index resides in the relocation entry
        */

        let core = self.core_ref();
        let reloc = self.relocation();
        let segments = core.segments();
        let base = core.base_addr();

        // Process each dynamic relocation entry
        for rel in reloc.dynrel {
            if !helper.handle_pre(rel)?.is_unhandled() {
                continue;
            }
            let r_type = rel.r_type();
            let r_sym = rel.r_symbol();
            let mut failure_reason = RelocReason::Unsupported;

            // Handle `REL_NONE` first because some architectures use `0` as a
            // sentinel for unsupported relocation classes such as TLSDESC.
            if r_type == Arch::NONE {
                continue;
            }

            if r_type == Arch::GOT || r_type == Arch::SYMBOLIC {
                // Handle GOT and symbolic relocations
                if let Some(symbol) = helper.find_symbol(r_sym) {
                    let r_addend = rel.r_addend(base.into_inner());
                    write_reloc_addr::<Arch>(segments, rel.r_offset(), symbol.addend(r_addend));
                    continue;
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if r_type == Arch::COPY {
                // Handle copy relocations (typically for global data)
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    if let Some(sym) = symdef.symbol() {
                        let len = core.symtab().symbol_idx(r_sym).0.st_size();
                        let dest = core.segments().get_slice_mut::<u8>(rel.r_offset(), len);
                        if let Some(src) = symdef.segment_slice(sym.st_value(), len) {
                            dest.copy_from_slice(src);
                            continue;
                        }
                    }
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if r_type == Arch::IRELATIVE {
                let r_addend = rel.r_addend(base.into_inner());
                let addr = base.addend(r_addend);
                if !Arch::SUPPORTS_NATIVE_RUNTIME {
                    if let Some(resolved) = helper.resolve_ifunc_with_emu(rel, addr)? {
                        write_reloc_addr::<Arch>(segments, rel.r_offset(), resolved);
                        continue;
                    }
                    failure_reason = RelocReason::MissingEmulator;
                } else {
                    write_reloc_addr::<Arch>(segments, rel.r_offset(), unsafe {
                        resolve_ifunc(addr)
                    });
                    continue;
                }
            } else if Arch::is_tls(r_type) {
                // `handle_tls_reloc` is a pure data computation for
                // DTPMOD/DTPOFF/TPOFF (safe under cross-arch loads) and
                // gates TLSDESC on SUPPORTS_NATIVE_RUNTIME internally.
                // Anything the built-in path cannot handle still gets a post
                // handler chance before reporting the specific TLS reason.
                match handle_tls_reloc::<_, Arch, _, _>(helper, rel)? {
                    TlsRelocOutcome::Applied => continue,
                    TlsRelocOutcome::Failed(reason) => failure_reason = reason,
                }
            }

            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel)?.is_unhandled() {
                return Err(reloc_error::<Arch, _>(rel, failure_reason, core));
            }
        }
        Ok(self)
    }
}

impl<Arch: RelocationArch> DynamicRelocation<Arch> {
    /// Create a new DynamicRelocation instance from parsed relocation data
    #[inline]
    pub(crate) fn new(
        pltrel: Option<&'static [ElfRelType<Arch>]>,
        dynrel: Option<&'static [ElfRelType<Arch>]>,
        relr: Option<&'static [ElfRelr<Arch::Layout>]>,
        rela_count: Option<NonZeroUsize>,
    ) -> Result<Self> {
        if let Some(relr) = relr {
            // Use RELR relocations if available (more compact format)
            Ok(Self {
                relative: RelativeRel::Relr(relr),
                pltrel: pltrel.unwrap_or(&[]),
                dynrel: dynrel.unwrap_or(&[]),
            })
        } else {
            // Use traditional REL/RELA relocations
            // nrelative indicates the count of REL_RELATIVE relocation types
            let nrelative = rela_count.map(|v| v.get()).unwrap_or(0);
            let old_dynrel = dynrel.unwrap_or(&[]);

            if nrelative > old_dynrel.len() {
                return Err(ParseDynamicError::MalformedRelocationTable {
                    detail:
                        "DT_RELCOUNT/DT_RELACOUNT relocation table is malformed: relative relocation count exceeds the relocation table length",
                }
                .into());
            }

            // Split relocations into relative and non-relative parts
            let relative = RelativeRel::Rel(&old_dynrel[..nrelative]);
            let temp_dynrel = &old_dynrel[nrelative..];

            let pltrel = pltrel.unwrap_or(&[]);
            let dynrel = if unsafe {
                // Check if dynrel and pltrel are contiguous in memory
                core::ptr::eq(
                    old_dynrel.as_ptr().add(old_dynrel.len()),
                    pltrel.as_ptr().add(pltrel.len()),
                )
            } {
                // If contiguous, exclude pltrel entries from dynrel
                let dynrel_len = temp_dynrel.len().checked_sub(pltrel.len()).ok_or(
                    ParseDynamicError::MalformedRelocationTable {
                        detail:
                            "DT_JMPREL relocation table is malformed: PLT relocations exceed the tail of DT_REL/DT_RELA",
                    },
                )?;
                &temp_dynrel[..dynrel_len]
            } else {
                // Otherwise, use all remaining entries
                temp_dynrel
            };

            Ok(Self {
                relative,
                pltrel,
                dynrel,
            })
        }
    }

    /// Check if there are no relocations to process
    #[inline]
    fn is_empty(&self) -> bool {
        self.relative.is_empty() && self.dynrel.is_empty() && self.pltrel.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::DynamicRelocation;
    use crate::{Error, ParseDynamicError, arch::NativeArch, elf::ElfRelType};
    use alloc::boxed::Box;
    use core::num::NonZeroUsize;

    fn zeroed_rel() -> ElfRelType {
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn rejects_relative_count_past_dynrel_len() {
        let dynrel = Box::leak(Box::new([zeroed_rel()]));
        let err = match DynamicRelocation::<NativeArch>::new(
            None,
            Some(&dynrel[..]),
            None,
            NonZeroUsize::new(2),
        ) {
            Ok(_) => panic!("relative count should be validated"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            Error::ParseDynamic(ParseDynamicError::MalformedRelocationTable { .. })
        ));
    }

    #[test]
    fn rejects_pltrel_suffix_longer_than_remaining_dynrel() {
        let dynrel = Box::leak(Box::new([zeroed_rel(), zeroed_rel(), zeroed_rel()]));
        let err = match DynamicRelocation::<NativeArch>::new(
            Some(&dynrel[..]),
            Some(&dynrel[..]),
            None,
            NonZeroUsize::new(1),
        ) {
            Ok(_) => panic!("contiguous PLT suffix should fit in the non-relative tail"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            Error::ParseDynamic(ParseDynamicError::MalformedRelocationTable { .. })
        ));
    }
}
