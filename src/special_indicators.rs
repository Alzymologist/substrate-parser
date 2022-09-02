//! Special decoding triggers and indicators.
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
use frame_metadata::v14::{RuntimeMetadataV14, SignedExtensionMetadata};
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, Field, Path, Type, TypeDef, Variant,
};

use crate::cards::Info;
use crate::decoding_sci::pick_variant;
use crate::error::ParserError;

/// [`Field`] `type_name` set indicating that the value *may* be
/// currency-related.
///
/// If the value is unsigned integer, it will be considered currency.
pub const BALANCE_ID_SET: &[&str] = &[
    "Balance",
    "BalanceOf<T>",
    "BalanceOf<T, I>",
    "DepositBalance",
    "ExtendedBalance",
    "PalletBalanceOf<T>",
    "T::Balance",
];

/// [`Field`] `name` set indicating the value *may* be nonce.
///
/// If the value is unsigned integer, it will be considered nonce.
pub const NONCE_ID_SET: &[&str] = &["nonce"];

/// [`Type`]-associated [`Path`] `ident` for [sp_core::crypto::AccountId32].
pub const ACCOUNT_ID32: &str = "AccountId32";

/// [`Type`]-associated [`Path`] `ident` indicating that the data to follow
/// *may* be a call.
pub const CALL: &str = "Call";

/// [`Type`]-associated [`Path`] `ident` for [sp_runtime::generic::Era].
pub const ERA: &str = "Era";

/// [`Type`]-associated [`Path`] `ident` indicating that the data to follow
/// *may* be an event.
pub const EVENT: &str = "Event";

/// [`Type`]-associated [`Path`] `ident` set for [sp_core::H160].
pub const H160: &[&str] = &["AccountId20", "H160"];

/// [`Type`]-associated [`Path`] `ident` for [sp_core::H256].
pub const H256: &str = "H256";

/// [`Type`]-associated [`Path`] `ident` for [sp_core::H512].
pub const H512: &str = "H512";

/// [`Type`]-associated [`Path`] `ident` indicating that the data to follow
/// *may* be an option.
pub const OPTION: &str = "Option";

/// [`Type`]-associated [`Path`] `ident` for [sp_arithmetic::Perbill].
pub const PERBILL: &str = "Perbill";

/// [`Type`]-associated [`Path`] `ident` for [sp_arithmetic::Percent].
pub const PERCENT: &str = "Percent";

/// [`Type`]-associated [`Path`] `ident` for [sp_arithmetic::Permill].
pub const PERMILL: &str = "Permill";

/// [`Type`]-associated [`Path`] `ident` for [sp_arithmetic::Perquintill].
pub const PERQUINTILL: &str = "Perquintill";

/// [`Type`]-associated [`Path`] `ident` for [sp_arithmetic::PerU16].
pub const PERU16: &str = "PerU16";

/// [`Type`]-associated [`Path`] `ident` for possible public key.
pub const PUBLIC: &str = "Public";

/// [`Type`]-associated [`Path`] `ident` for possible signature.
pub const SIGNATURE: &str = "Signature";

/// [`Path`] `namespace` for [sp_core::ed25519].
pub const SP_CORE_ED25519: &[&str] = &["sp_core", "ed25519"];

/// [`Path`] `namespace` for [sp_core::sr25519].
pub const SP_CORE_SR25519: &[&str] = &["sp_core", "sr25519"];

/// [`Path`] `namespace` for [sp_core::ecdsa].
pub const SP_CORE_ECDSA: &[&str] = &["sp_core", "ecdsa"];

/// [`Variant`] name `None` that must be found for type to be processed as
/// `Option`.
pub const NONE: &str = "None";

/// [`Variant`] name `Some` that must be found for type to be processed as
/// `Option`.
pub const SOME: &str = "Some";

/// Extensions `identifier` from [`SignedExtensionMetadata`] for metadata spec
/// version.
///
/// If underlying value is unsigned integer, it will be considered spec version.
///
/// Apparently established `identifier` across different chains.
pub const CHECK_SPEC_VERSION: &str = "CheckSpecVersion";

/// Extensions `identifier` from [`SignedExtensionMetadata`] for tx version.
///
/// If underlying value is unsigned integer, it will be considered tx version.
///
/// Apparently established `identifier` across different chains.
pub const CHECK_TX_VERSION: &str = "CheckTxVersion";

/// Extensions `identifier` from [`SignedExtensionMetadata`] for chain genesis
/// hash.
///
/// If underlying value is `H256`, it will be considered genesis hash.
///
/// Apparently established `identifier` across different chains.
pub const CHECK_GENESIS: &str = "CheckGenesis";

/// Extensions `identifier` from [`SignedExtensionMetadata`] for block hash.
///
/// If underlying value is `H256`, it will be considered block hash.
///
/// Same identifier accompanies `Era` in extensions, but `Era` gets detected by
/// matching [`Path`] of the corresponding [`Type`] with [`ERA`].
///
/// Apparently established `identifier` across different chains.
pub const CHECK_MORTALITY: &str = "CheckMortality";

/// Extensions `identifier` from [`SignedExtensionMetadata`] for nonce.
///
/// If underlying value is unsigned integer, it will be considered nonce.
///
/// Apparently established `identifier` across different chains.
pub const CHECK_NONCE: &str = "CheckNonce";

/// Extensions `identifier` from [`SignedExtensionMetadata`] for transaction
/// tip.
///
/// If underlying value is unsigned integer, it will be considered tip.
///
/// Note: signable transaction tip always gets carded as balance with chain
/// units and decimals.
///
/// Apparently established `identifier` across different chains.
pub const CHARGE_TRANSACTION_PAYMENT: &str = "ChargeTransactionPayment";

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
    pub fn from_field(field: &Field<PortableForm>) -> Self {
        let mut out = match field.name() {
            Some(name) => match name.as_str() {
                a if NONCE_ID_SET.contains(&a) => Self::FieldNonce,
                _ => Self::None,
            },
            None => Self::None,
        };
        if let Self::None = out {
            if let Some(type_name) = field.type_name() {
                out = match type_name.as_str() {
                    a if BALANCE_ID_SET.contains(&a) => Self::FieldBalance,
                    _ => Self::None,
                };
            }
        }
        out
    }

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
    /// `H256` type.
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
            Err(ParserError::UnexpectedCompactInsides)
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
            CHECK_SPEC_VERSION => Hint::CheckSpecVersion,
            CHECK_TX_VERSION => Hint::CheckTxVersion,
            CHECK_GENESIS => Hint::CheckGenesis,
            CHECK_MORTALITY => Hint::CheckMortality,
            CHECK_NONCE => Hint::CheckNonce,
            CHARGE_TRANSACTION_PAYMENT => Hint::ChargeTransactionPayment,
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
    Option,
    PalletSpecific(PalletSpecificItem),
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
                CALL => Self::PalletSpecific(PalletSpecificItem::Call),
                EVENT => Self::PalletSpecific(PalletSpecificItem::Event),
                OPTION => Self::Option,
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
    PublicEd25519,
    PublicSr25519,
    PublicEcdsa,
    SignatureEd25519,
    SignatureSr25519,
    SignatureEcdsa,
}

impl<'a> SpecialtyTypeChecked<'a> {
    pub fn from_type(
        ty: &'a Type<PortableForm>,
        data: &mut Vec<u8>,
        meta_v14: &'a RuntimeMetadataV14,
    ) -> Self {
        let path = ty.path();
        match SpecialtyTypeHinted::from_path(path) {
            SpecialtyTypeHinted::Option => {
                if let TypeDef::Variant(x) = ty.type_def() {
                    let params = ty.type_params();
                    if params.len() == 1 {
                        if let Some(ty_symbol) = params[0].ty() {
                            let mut has_none = false;
                            let mut has_some = false;
                            for variant in x.variants() {
                                if variant.index() == 0 && variant.name() == NONE {
                                    has_none = true
                                }
                                if variant.index() == 1 && variant.name() == SOME {
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
            SpecialtyTypeHinted::None => match path.ident() {
                Some(a) => match a.as_str() {
                    ACCOUNT_ID32 => Self::AccountId32,
                    ERA => Self::Era,
                    a if H160.contains(&a) => Self::H160,
                    H256 => Self::H256,
                    H512 => Self::H512,
                    PERBILL => Self::Perbill,
                    PERCENT => Self::Percent,
                    PERMILL => Self::Permill,
                    PERQUINTILL => Self::Perquintill,
                    PERU16 => Self::PerU16,
                    PUBLIC => match path
                        .namespace()
                        .iter()
                        .map(|x| x.as_str())
                        .collect::<Vec<&str>>()
                        .as_ref()
                    {
                        SP_CORE_ED25519 => Self::PublicEd25519,
                        SP_CORE_SR25519 => Self::PublicSr25519,
                        SP_CORE_ECDSA => Self::PublicEcdsa,
                        _ => Self::None,
                    },
                    SIGNATURE => match path
                        .namespace()
                        .iter()
                        .map(|x| x.as_str())
                        .collect::<Vec<&str>>()
                        .as_ref()
                    {
                        SP_CORE_ED25519 => Self::SignatureEd25519,
                        SP_CORE_SR25519 => Self::SignatureSr25519,
                        SP_CORE_ECDSA => Self::SignatureEcdsa,
                        _ => Self::None,
                    },
                    _ => Self::None,
                },
                None => Self::None,
            },
        }
    }
}
