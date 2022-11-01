//! Data that can propagate hierarchically during parsing.
use frame_metadata::v14::SignedExtensionMetadata;
use scale_info::{form::PortableForm, interner::UntrackedSymbol, Field};

use crate::cards::Info;
use crate::error::ParserError;
use crate::special_indicators::{Hint, SpecialtyH256, SpecialtyPrimitive};

/// Type specialty data (type specialty [`Hint`] and compact info) that
/// hierarchically propagates during the decoding.
///
/// Compact flag impacts decoding. [`Hint`] can determine only the decoded data
/// further processing.
#[derive(Clone, Copy, Debug)]
pub struct SpecialtySet {
    /// Compact flag.
    ///
    /// True if the parser has encountered type with a type definition
    /// `TypeDef::Compact(_)` for this `SpecialtySet` instance. Once true, never
    /// gets removed from an instance.
    ///
    /// Must cause parser error if `true`, but the type inside compact has no
    /// [`HasCompact`](parity_scale_codec::HasCompact) implementation.
    ///
    /// Currently is allowed to be `true` for unsigned integers and single-field
    /// structs with unsigned integer as a field.
    pub is_compact: bool,

    /// `Hint` the parser has encountered for this `SpecialtySet` instance.
    ///
    /// Does not cause parser errors even if resolved type is incompatible.
    ///
    /// Could be nullified if no longer relevant, i.e. if passed through some
    /// type that is hint-incompatible.
    pub hint: Hint,
}

impl SpecialtySet {
    /// Initiate new `SpecialtySet`.
    pub fn new() -> Self {
        Self {
            is_compact: false,
            hint: Hint::None,
        }
    }

    /// Check that `is_compact` field is not `true`.
    pub fn reject_compact(&self) -> Result<(), ParserError> {
        if self.is_compact {
            Err(ParserError::UnexpectedCompactInsides)
        } else {
            Ok(())
        }
    }

    /// Previously found `Hint` (if there was any) is no longer relevant and is
    /// discarded.
    pub fn forget_hint(&mut self) {
        self.hint = Hint::None;
    }

    /// Apply `hint` field on unsigned integer decoding.
    pub fn primitive(&self) -> SpecialtyPrimitive {
        self.hint.primitive()
    }

    /// Apply `hint` field on `H256` decoding.
    pub fn hash256(&self) -> SpecialtyH256 {
        self.hint.hash256()
    }
}

impl Default for SpecialtySet {
    fn default() -> Self {
        Self::new()
    }
}

/// Types data collected and checked during parsing ([`SpecialtySet`] and
/// type id collection to prevent cycling).
#[derive(Clone, Debug)]
pub struct Checker {
    /// `SpecialtySet` initiated new and modified during decoding.
    pub specialty_set: SpecialtySet,

    /// Collection of encountered so far during decoding type `id`s from
    /// metadata types `Registry`, to catch possible endless type resolver
    /// cycles.
    pub cycle_check: Vec<u32>,
}

impl Checker {
    /// Initiate new `Checker` in decoding sequence.
    pub fn new() -> Self {
        Self {
            specialty_set: SpecialtySet::new(),
            cycle_check: Vec::new(),
        }
    }

    /// Check that `is_compact` field in associated [`SpecialtySet`] is not
    /// `true`.
    pub fn reject_compact(&self) -> Result<(), ParserError> {
        self.specialty_set.reject_compact()
    }

    /// Discard previously found [`Hint`].
    pub fn forget_hint(&mut self) {
        self.specialty_set.forget_hint()
    }

    /// Use known, propagated from above `Checker` to construct a new `Checker`
    /// for an individual [`Field`].
    pub fn update_for_field(&self, field: &Field<PortableForm>) -> Result<Self, ParserError> {
        let mut checker = self.clone();

        // update `Hint`
        if let Hint::None = checker.specialty_set.hint {
            checker.specialty_set.hint = Hint::from_field(field);
        }

        // check that `id` is not cycling and update `id` set
        checker.check_id(field.ty().id())?;

        Ok(checker)
    }

    /// Use known, propagated from above `Checker` to construct a new `Checker`
    /// for a [`Type`](scale_info::Type).
    pub fn update_for_ty_symbol(
        &self,
        ty_symbol: &UntrackedSymbol<std::any::TypeId>,
    ) -> Result<Self, ParserError> {
        let mut checker = self.clone();
        checker.check_id(ty_symbol.id())?;
        Ok(checker)
    }

    /// Discard previously collected `cycle_check` set.
    ///
    /// For cases when `Checker` keeps propagating, but decoded data itself has
    /// changed.
    pub fn drop_cycle_check(&mut self) {
        self.cycle_check.clear()
    }

    /// Check new type `id`.
    ///
    /// If type was already encountered in this `Checker` (and thus its `id` is
    /// in `cycle_check`), the decoding has entered a cycle and must be stopped.
    /// If not, type `id` is added into `cycle_check`.
    pub fn check_id(&mut self, id: u32) -> Result<(), ParserError> {
        if self.cycle_check.contains(&id) {
            Err(ParserError::CyclicMetadata { id })
        } else {
            self.cycle_check.push(id);
            Ok(())
        }
    }
}

impl Default for Checker {
    fn default() -> Self {
        Self::new()
    }
}

/// Propagating data and collected type information (`Checker` and all non-empty
/// type info).
#[derive(Clone, Debug)]
pub struct Propagated {
    /// Type data that is collected and checked during parsing.
    pub(crate) checker: Checker,

    /// Set of [`Info`] collected while resolving the type.
    ///
    /// Only non-empty [`Info`] entries are added.
    pub(crate) info: Vec<Info>,
}

impl Propagated {
    /// Initiate new `Propagated` in decoding sequence.
    pub fn new() -> Self {
        Self {
            checker: Checker::new(),
            info: Vec::new(),
        }
    }

    /// Initiate new `Propagated` for signed extensions instance.
    pub(crate) fn from_ext_meta(signed_ext_meta: &SignedExtensionMetadata<PortableForm>) -> Self {
        Self {
            checker: Checker {
                specialty_set: SpecialtySet {
                    is_compact: false,
                    hint: Hint::from_ext_meta(signed_ext_meta),
                },
                cycle_check: Vec::new(),
            },
            info: Vec::new(),
        }
    }

    /// Initiate new `Propagated` with known, propagated from above `Checker`.
    pub(crate) fn with_checker(checker: Checker) -> Self {
        Self {
            checker,
            info: Vec::new(),
        }
    }

    /// Initiate new `Propagated` with known, propagated from above `Checker`
    /// for an individual [`Field`].
    pub(crate) fn for_field(
        checker: &Checker,
        field: &Field<PortableForm>,
    ) -> Result<Self, ParserError> {
        Ok(Self {
            checker: Checker::update_for_field(checker, field)?,
            info: Vec::new(),
        })
    }

    /// Initiate new `Propagated` with known, propagated from above `Checker`
    /// for a [`Type`](scale_info::Type).
    pub(crate) fn for_ty_symbol(
        checker: &Checker,
        ty_symbol: &UntrackedSymbol<std::any::TypeId>,
    ) -> Result<Self, ParserError> {
        Ok(Self {
            checker: Checker::update_for_ty_symbol(checker, ty_symbol)?,
            info: Vec::new(),
        })
    }

    /// Get associated `is_compact`
    pub(crate) fn is_compact(&self) -> bool {
        self.checker.specialty_set.is_compact
    }

    /// Check that `is_compact` field in associated [`SpecialtySet`] is not
    /// `true`.
    pub(crate) fn reject_compact(&self) -> Result<(), ParserError> {
        self.checker.specialty_set.reject_compact()
    }

    /// Discard previously found [`Hint`].
    pub(crate) fn forget_hint(&mut self) {
        self.checker.forget_hint()
    }

    /// Add [`Info`] entry (if non-empty) to `info` set.
    pub(crate) fn add_info(&mut self, info_update: &Info) {
        if !info_update.is_empty() {
            self.info.push(info_update.clone())
        }
    }

    /// Add `&[Info]` to `info` set.
    pub(crate) fn add_info_slice(&mut self, info_update_slice: &[Info]) {
        self.info.extend_from_slice(info_update_slice)
    }
}

impl Default for Propagated {
    fn default() -> Self {
        Self::new()
    }
}
