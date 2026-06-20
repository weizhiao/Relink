#[cfg(feature = "tls")]
mod enabled {
    use super::super::defs::{
        TlsDescDynamicArg, TlsImageSource, TlsInfo, TlsModuleId, TlsTemplate, TlsTpOffset,
    };
    use crate::{Result, memory::MappedView};
    use alloc::{boxed::Box, vec::Vec};
    use core::cell::OnceCell;

    /// Stores descriptor args behind stable allocations because relocated
    /// TLSDESC entries keep raw pointers to individual args.
    #[allow(clippy::vec_box)]
    #[derive(Default)]
    pub(crate) struct TlsDescArgs(Vec<Box<TlsDescDynamicArg>>);

    impl TlsDescArgs {
        pub(crate) fn push(&mut self, arg: Box<TlsDescDynamicArg>) {
            self.0.push(arg);
        }
    }

    #[derive(Default)]
    pub(crate) struct CoreTlsDescArgs {
        args: OnceCell<Box<[Box<TlsDescDynamicArg>]>>,
    }

    impl CoreTlsDescArgs {
        pub(crate) fn set(&self, args: TlsDescArgs) {
            assert!(
                self.args.set(args.0.into_boxed_slice()).is_ok(),
                "TLS descriptor arguments must be set only once",
            );
        }
    }

    struct TlsModuleState {
        mod_id: Option<TlsModuleId>,
        tp_offset: Option<TlsTpOffset>,
    }

    impl TlsModuleState {
        #[inline]
        const fn new(mod_id: Option<TlsModuleId>, tp_offset: Option<TlsTpOffset>) -> Self {
            Self { mod_id, tp_offset }
        }
    }

    struct TlsBackend {
        unregister: fn(TlsModuleId),
        init_tls: fn(TlsImageSource, TlsModuleId, Option<TlsTpOffset>) -> Result<()>,
    }

    impl TlsBackend {
        #[inline]
        const fn new(
            unregister: fn(TlsModuleId),
            init_tls: fn(TlsImageSource, TlsModuleId, Option<TlsTpOffset>) -> Result<()>,
        ) -> Self {
            Self {
                unregister,
                init_tls,
            }
        }
    }

    /// TLS runtime state attached to a loaded ELF core.
    ///
    /// This keeps TLS-specific bookkeeping out of `CoreInner`, so TLS state can
    /// collapse to an empty implementation when the `tls` feature is disabled.
    pub(crate) struct CoreTlsState {
        module: TlsModuleState,
        template: Option<TlsTemplate<'static>>,
        backend: TlsBackend,
    }

    impl CoreTlsState {
        pub(crate) fn new(
            mod_id: Option<TlsModuleId>,
            tp_offset: Option<TlsTpOffset>,
            info: Option<TlsInfo>,
            image: Option<MappedView<u8>>,
            unregister: fn(TlsModuleId),
            init_tls: fn(TlsImageSource, TlsModuleId, Option<TlsTpOffset>) -> Result<()>,
        ) -> Option<Self> {
            debug_assert_eq!(
                info.is_some(),
                image.is_some(),
                "TLS template metadata and image must be provided together",
            );
            debug_assert!(
                mod_id.is_some() || info.is_none(),
                "TLS template state must not exist without a module ID",
            );
            if mod_id.is_none() && info.is_none() {
                return None;
            }

            Some(Self {
                module: TlsModuleState::new(mod_id, tp_offset),
                template: info
                    .zip(image)
                    .map(|(info, image)| info.template(image.as_slice())),
                backend: TlsBackend::new(unregister, init_tls),
            })
        }

        #[inline]
        pub(crate) fn mod_id(&self) -> Option<TlsModuleId> {
            self.module.mod_id
        }

        #[inline]
        pub(crate) fn tp_offset(&self) -> Option<TlsTpOffset> {
            self.module.tp_offset
        }

        #[inline]
        pub(crate) fn cleanup(&self) {
            if let Some(mod_id) = self.module.mod_id {
                (self.backend.unregister)(mod_id);
            }
        }

        #[inline]
        pub(crate) fn info(&self) -> Option<TlsInfo> {
            self.template.map(|template| template.info)
        }

        pub(crate) fn with_template(
            &self,
            f: &mut dyn FnMut(TlsTemplate<'_>) -> Result<()>,
        ) -> Result<()> {
            let template = self
                .template
                .expect("TLS image provider must have a template");
            f(template)
        }

        pub(crate) fn init_tls(&self, source: TlsImageSource) -> Result<()> {
            let Some(mod_id) = self.module.mod_id else {
                return Ok(());
            };
            debug_assert!(
                self.template.is_some(),
                "TLS module state must have a template before initialization",
            );
            (self.backend.init_tls)(source, mod_id, self.module.tp_offset)
        }
    }
}

#[cfg(not(feature = "tls"))]
mod disabled {
    use super::super::defs::{TlsImageSource, TlsInfo, TlsModuleId, TlsTemplate, TlsTpOffset};
    use crate::{Result, memory::MappedView};

    #[derive(Default)]
    pub(crate) struct TlsDescArgs;

    #[derive(Default)]
    pub(crate) struct CoreTlsDescArgs;

    impl CoreTlsDescArgs {
        pub(crate) fn set(&self, _args: TlsDescArgs) {}
    }

    /// TLS runtime state attached to a loaded ELF core.
    ///
    /// This keeps TLS-specific bookkeeping out of `CoreInner`, so TLS state can
    /// collapse to an empty implementation when the `tls` feature is disabled.
    pub(crate) struct CoreTlsState;

    impl CoreTlsState {
        pub(crate) fn new(
            _mod_id: Option<TlsModuleId>,
            _tp_offset: Option<TlsTpOffset>,
            _info: Option<TlsInfo>,
            _image: Option<MappedView<u8>>,
            _unregister: fn(TlsModuleId),
            _init_tls: fn(TlsImageSource, TlsModuleId, Option<TlsTpOffset>) -> Result<()>,
        ) -> Option<Self> {
            None
        }

        #[inline]
        pub(crate) fn mod_id(&self) -> Option<TlsModuleId> {
            None
        }

        #[inline]
        pub(crate) fn tp_offset(&self) -> Option<TlsTpOffset> {
            None
        }

        #[inline]
        pub(crate) fn cleanup(&self) {}

        #[inline]
        pub(crate) fn info(&self) -> Option<TlsInfo> {
            None
        }

        pub(crate) fn with_template(
            &self,
            _f: &mut dyn FnMut(TlsTemplate<'_>) -> Result<()>,
        ) -> Result<()> {
            Ok(())
        }

        pub(crate) fn init_tls(&self, _source: TlsImageSource) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(feature = "tls")]
pub(crate) use enabled::{CoreTlsDescArgs, CoreTlsState, TlsDescArgs};

#[cfg(not(feature = "tls"))]
pub(crate) use disabled::{CoreTlsDescArgs, CoreTlsState, TlsDescArgs};
