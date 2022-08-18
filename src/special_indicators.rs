//! Special decoding triggers and indicators
//!
//! Although the [`RuntimeMetadataV14`] has all sufficient data to decode the
//! data for a known type, some types must be treated specially for displaying
//! and/or further data handling.
//!
//! Additionally, some data should better be decoded directly as the custom type
//! mentioned in metadata descriptors, rather than decoded as more generalized
//! type and cast into custom type later on.
//!
//! Reasonable balance between bringing in external types and clean universal
//! decoder is difficult to find, and improvement suggestions are welcome.
//!
//! There are several specialty indicators that are getting checked:
//!
//! - [`Path`] associated with [`Type`], in particular its `ident` part, which
//! leads to:
//!     - definitive decoding route (`Perthing` types, `Era`, `AccountId32`)
//!     - definitive decoding route if essential inner details are matching the
//! ones expected (`Call`, `Option`)
//!
//!

use frame_metadata::v14::{RuntimeMetadataV14, SignedExtensionMetadata};
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, Field, Path, Type, TypeDef, Variant,
};

use crate::cards::Info;
use crate::decoding_sci::pick_variant;
use crate::error::{ParserDecodingError, ParserError};

#[derive(Clone, Copy, Debug)]
pub enum SpecialtyPrimitive {
    None,
    Balance,
    Tip,
    Nonce,
    SpecVersion,
    TxVersion,
}

#[derive(Clone, Copy, Debug)]
pub enum SpecialtyH256 {
    None,
    GenesisHash,
    BlockHash,
}

#[derive(Clone, Copy, Debug)]
pub enum Hint {
    None,
    CheckSpecVersion,
    CheckTxVersion,
    CheckGenesis,
    CheckMortality,
    CheckNonce,
    ChargeTransactionPayment,
    FieldBalance,
    FieldNonce,
}

impl Hint {
    /// Propagated [`Hint`] has reached the primitive decoding.
    ///
    /// If hint is compatible with the primitive type encountered, it is used.
    pub fn primitive(&self) -> SpecialtyPrimitive {
        match &self {
            Hint::CheckSpecVersion => SpecialtyPrimitive::SpecVersion,
            Hint::CheckTxVersion => SpecialtyPrimitive::TxVersion,
            Hint::CheckNonce | Hint::FieldNonce => SpecialtyPrimitive::Nonce,
            Hint::ChargeTransactionPayment => SpecialtyPrimitive::Tip,
            Hint::FieldBalance => SpecialtyPrimitive::Balance,
            _ => SpecialtyPrimitive::None,
        }
    }

    /// Propagated [`Hint`] has reached the decoding as a specialty with
    /// [`H256`] type.
    ///
    /// If hint is compatible with the primitive type encountered, it is used.
    pub fn hash256(&self) -> SpecialtyH256 {
        match &self {
            Hint::CheckGenesis => SpecialtyH256::GenesisHash,
            Hint::CheckMortality => SpecialtyH256::BlockHash,
            _ => SpecialtyH256::None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SpecialtySet {
    pub is_compact: bool,
    pub hint: Hint,
}

impl SpecialtySet {
    pub fn new() -> Self {
        Self {
            is_compact: false,
            hint: Hint::None,
        }
    }
    pub fn reject_compact(&self) -> Result<(), ParserError> {
        if self.is_compact {
            Err(ParserError::Decoding(
                ParserDecodingError::UnexpectedCompactInsides,
            ))
        } else {
            Ok(())
        }
    }
    pub fn primitive(&self) -> SpecialtyPrimitive {
        self.hint.primitive()
    }
    pub fn hash256(&self) -> SpecialtyH256 {
        self.hint.hash256()
    }
}

impl Default for SpecialtySet {
    fn default() -> Self {
        Self::new()
    }
}

/// Propagating type info
#[derive(Clone, Debug)]
pub struct Propagated {
    pub specialty_set: SpecialtySet,

    /// Set of [`Info`] collected while resolving the type.
    ///
    /// Only non-empty [`Info`] entries are added.
    pub info: Vec<Info>,
}

impl Propagated {
    pub fn new() -> Self {
        Self {
            specialty_set: SpecialtySet::new(),
            info: Vec::new(),
        }
    }
    pub fn with_compact(is_compact: bool) -> Self {
        Self {
            specialty_set: SpecialtySet {
                is_compact,
                hint: Hint::None,
            },
            info: Vec::new(),
        }
    }
    pub fn with_specialty_set(specialty_set: SpecialtySet) -> Self {
        Self {
            specialty_set,
            info: Vec::new(),
        }
    }
    pub fn with_specialty_set_updated(mut specialty_set: SpecialtySet, hint: Hint) -> Self {
        if let Hint::None = specialty_set.hint {
            specialty_set.hint = hint;
        }
        Self {
            specialty_set,
            info: Vec::new(),
        }
    }
    pub fn add_info(&mut self, info_update: &Info) {
        if !info_update.is_empty() {
            self.info.push(info_update.clone())
        }
    }
    pub fn add_info_slice(&mut self, info_update_slice: &[Info]) {
        self.info.extend_from_slice(info_update_slice)
    }
    pub fn from_ext_meta(signed_ext_meta: &SignedExtensionMetadata<PortableForm>) -> Self {
        let hint = match signed_ext_meta.identifier.as_str() {
            "CheckSpecVersion" => Hint::CheckSpecVersion,
            "CheckTxVersion" => Hint::CheckTxVersion,
            "CheckGenesis" => Hint::CheckGenesis,
            "CheckMortality" => Hint::CheckMortality,
            "CheckNonce" => Hint::CheckNonce,
            "ChargeTransactionPayment" => Hint::ChargeTransactionPayment,
            _ => Hint::None,
        };
        Self {
            specialty_set: SpecialtySet {
                is_compact: false,
                hint,
            },
            info: Vec::new(),
        }
    }
}

impl Default for Propagated {
    fn default() -> Self {
        Self::new()
    }
}

pub enum Lead {
    Text,
}

pub enum SpecialtyField {
    Lead(Lead),
    Hint(Hint),
    None,
}

impl SpecialtyField {
    pub fn from_field(field: &Field<PortableForm>) -> Self {
        let mut out = match field.name() {
            Some(name) => match name.as_str() {
                "remark" | "remark_with_event" => Self::Lead(Lead::Text),
                "nonce" => Self::Hint(Hint::FieldNonce),
                _ => Self::None,
            },
            None => Self::None,
        };
        if let Self::None = out {
            if let Some(type_name) = field.type_name() {
                out = match type_name.as_str() {
                    "Balance" | "T::Balance" | "BalanceOf<T>" | "ExtendedBalance"
                    | "BalanceOf<T, I>" | "DepositBalance" | "PalletBalanceOf<T>" => {
                        Self::Hint(Hint::FieldBalance)
                    }
                    _ => Self::None,
                };
            }
        }
        out
    }
}

/// Specialty found from `path` of the [`Type`].
///
/// Allows to decode data as as custom known types and to display data better.
///
/// Becomes other than `None` if a [`Type`] has recognizable `ident` component
/// of the [`Path`].
///
/// If found, **tries** sending decoding through a special decoding route.
///
/// Gets checked each time a new type is encountered.
pub enum SpecialtyTypeHinted {
    None,
    AccountId32,
    Era,
    H160,
    H256,
    H512,
    Option,
    PalletSpecific(PalletSpecificItem),
    Perbill,
    Percent,
    Permill,
    Perquintill,
    PerU16,
}

#[derive(Debug, PartialEq)]
pub enum PalletSpecificItem {
    Call,
    Event,
}

impl SpecialtyTypeHinted {
    pub fn from_path(path: &Path<PortableForm>) -> Self {
        match path.ident() {
            Some(a) => match a.as_str() {
                "AccountId32" => Self::AccountId32,
                "Call" => Self::PalletSpecific(PalletSpecificItem::Call),
                "Era" => Self::Era,
                "Event" => Self::PalletSpecific(PalletSpecificItem::Event),
                "H160" => Self::H160,
                "H256" => Self::H256,
                "H512" => Self::H512,
                "Option" => Self::Option,
                "Perbill" => Self::Perbill,
                "Percent" => Self::Percent,
                "Permill" => Self::Permill,
                "Perquintill" => Self::Perquintill,
                "PerU16" => Self::PerU16,
                _ => Self::None,
            },
            None => Self::None,
        }
    }
}

pub enum SpecialtyTypeChecked<'a> {
    None,
    AccountId32,
    Era,
    H160,
    H256,
    H512,
    Option(&'a UntrackedSymbol<std::any::TypeId>),
    PalletSpecific {
        pallet_name: String,
        pallet_info: Info,
        variants: &'a [Variant<PortableForm>],
        item: PalletSpecificItem,
    },
    Perbill,
    Percent,
    Permill,
    Perquintill,
    PerU16,
}

impl<'a> SpecialtyTypeChecked<'a> {
    pub fn from_type(
        ty: &'a Type<PortableForm>,
        data: &mut Vec<u8>,
        meta_v14: &'a RuntimeMetadataV14,
    ) -> Self {
        match SpecialtyTypeHinted::from_path(ty.path()) {
            SpecialtyTypeHinted::AccountId32 => Self::AccountId32,
            SpecialtyTypeHinted::Era => Self::Era,
            SpecialtyTypeHinted::H160 => Self::H160,
            SpecialtyTypeHinted::H256 => Self::H256,
            SpecialtyTypeHinted::H512 => Self::H512,
            SpecialtyTypeHinted::Option => {
                if let TypeDef::Variant(x) = ty.type_def() {
                    let params = ty.type_params();
                    if params.len() == 1 {
                        if let Some(ty_symbol) = params[0].ty() {
                            let mut has_none = false;
                            let mut has_some = false;
                            for variant in x.variants() {
                                if variant.index() == 0 && variant.name() == "None" {
                                    has_none = true
                                }
                                if variant.index() == 1 && variant.name() == "Some" {
                                    has_some = true
                                }
                            }
                            if has_none && has_some && (x.variants().len() == 2) {
                                Self::Option(ty_symbol)
                            } else {
                                Self::None
                            }
                        } else {
                            Self::None
                        }
                    } else {
                        Self::None
                    }
                } else {
                    Self::None
                }
            }
            SpecialtyTypeHinted::PalletSpecific(item) => {
                if let TypeDef::Variant(x) = ty.type_def() {
                    // found specific variant corresponding to pallet,
                    // get pallet name from here
                    match pick_variant(x.variants(), data) {
                        Ok(pallet_variant) => {
                            let pallet_name = pallet_variant.name().to_owned();
                            let pallet_fields = pallet_variant.fields();
                            if pallet_fields.len() == 1 {
                                match meta_v14.types.resolve(pallet_fields[0].ty().id()) {
                                    Some(variants_ty) => {
                                        if let SpecialtyTypeHinted::PalletSpecific(item_repeated) =
                                            SpecialtyTypeHinted::from_path(variants_ty.path())
                                        {
                                            if item != item_repeated {
                                                Self::None
                                            } else if let TypeDef::Variant(var) =
                                                variants_ty.type_def()
                                            {
                                                let pallet_info = Info::from_ty(variants_ty);
                                                *data = data[1..].to_vec();
                                                Self::PalletSpecific {
                                                    pallet_name,
                                                    pallet_info,
                                                    variants: var.variants(),
                                                    item,
                                                }
                                            } else {
                                                Self::None
                                            }
                                        } else {
                                            Self::None
                                        }
                                    }
                                    None => Self::None,
                                }
                            } else {
                                Self::None
                            }
                        }
                        Err(_) => Self::None,
                    }
                } else {
                    Self::None
                }
            }
            SpecialtyTypeHinted::Perbill => Self::Perbill,
            SpecialtyTypeHinted::Percent => Self::Percent,
            SpecialtyTypeHinted::Permill => Self::Permill,
            SpecialtyTypeHinted::Perquintill => Self::Perquintill,
            SpecialtyTypeHinted::PerU16 => Self::PerU16,
            SpecialtyTypeHinted::None => Self::None,
        }
    }
}
