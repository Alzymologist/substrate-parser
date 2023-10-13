//! Types for parsed data (nested) and parser cards (flat and formatted).
use bitvec::prelude::{BitVec, Lsb0, Msb0};
use frame_metadata::v14::StorageEntryMetadata;
use num_bigint::{BigInt, BigUint};
use primitive_types::{H160, H256, H512};
use scale_info::{form::PortableForm, Field, Path, Type, Variant};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};

#[cfg(not(feature = "std"))]
use crate::additional_types::{
    AccountId32, PublicEcdsa, PublicEd25519, PublicSr25519, SignatureEcdsa, SignatureEd25519,
    SignatureSr25519,
};
#[cfg(feature = "std")]
use sp_core::{
    crypto::{AccountId32, Ss58AddressFormat, Ss58Codec},
    ecdsa::{Public as PublicEcdsa, Signature as SignatureEcdsa},
    ed25519::{Public as PublicEd25519, Signature as SignatureEd25519},
    sr25519::{Public as PublicSr25519, Signature as SignatureSr25519},
};

#[cfg(not(feature = "std"))]
use crate::additional_types::Era;
#[cfg(feature = "std")]
use sp_runtime::generic::Era;

#[cfg(feature = "std")]
use plot_icon::generate_png_scaled_default;

use crate::std::{
    borrow::ToOwned,
    boxed::Box,
    fmt::Write,
    string::{String, ToString},
    vec::Vec,
};

use crate::printing_balance::{AsBalance, Currency};
use crate::special_indicators::{PalletSpecificItem, SpecialtyStr, SpecialtyUnsignedInteger};
use crate::ShortSpecs;

/// Type-associated information from the metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Info {
    /// Documentation from metadata, collected into single `String`.
    pub docs: String,

    /// [`Path`], copied from the metadata verbatim.
    ///
    /// Could be used to locate parsed information pieces by known path
    /// elements.
    pub path: Path<PortableForm>,
}

impl Info {
    /// Collect available info for a [`Type`].
    pub fn from_ty(ty: &Type<PortableForm>) -> Self {
        Self {
            docs: ty.collect_docs(),
            path: ty.path.to_owned(),
        }
    }

    /// Check if `Info` is empty, i.e. there are neither docs nor path
    /// available.
    ///
    /// Only non-empty `Info` entries are added to info set.
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty() && self.path.is_empty()
    }

    /// Transform `Info` (used in `ExtendedData`) into `InfoFlat` (used in flat
    /// cards `ExtendedCard`).
    pub fn flatten(&self) -> InfoFlat {
        let docs = {
            if self.docs.is_empty() {
                None
            } else {
                Some(self.docs.to_owned())
            }
        };
        let path_flat = {
            if self.path.is_empty() {
                None
            } else {
                Some(self.path.segments.join(" >> "))
            }
        };
        InfoFlat { docs, path_flat }
    }
}

/// Helper trait for [`scale_info`] entities having documentation.
pub trait Documented {
    fn collect_docs(&self) -> String;
}

/// Collect documentation from documented [`scale_info`] entity ([`Type`],
/// [`Field`], [`Variant`], [`StorageEntryMetadata<PortableForm>`]).
macro_rules! impl_documented {
    ($($ty: ty), *) => {
        $(
            impl Documented for $ty {
                fn collect_docs(&self) -> String {
                    self.docs.join("\n")
                }
            }
        )*
    }
}

impl_documented!(
    Type<PortableForm>,
    Field<PortableForm>,
    Variant<PortableForm>,
    StorageEntryMetadata<PortableForm>
);

/// Parsed data and collected relevant type information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedData {
    /// Parsed data, nested.
    pub data: ParsedData,

    /// All non-empty `Info` encountered while resolving the type.
    pub info: Vec<Info>,
}

/// Parsed data for [`PalletSpecificItem`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PalletSpecificData {
    pub pallet_info: Info,
    pub variant_docs: String,
    pub pallet_name: String,
    pub variant_name: String,
    pub fields: Vec<FieldData>,
}

/// Parsed Call data. Nested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Call(pub PalletSpecificData);

/// Parsed Event data. Nested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event(pub PalletSpecificData);

/// List of pallets in which the currency-related value gets displayed with
/// with chain units and decimals.
pub const PALLETS_BALANCE_VALID: &[&str] = &["Balances", "Staking"];

impl PalletSpecificData {
    /// Should the balance value in the `PalletSpecificData` be displayed as a
    /// balance with chain decimals and units?
    ///
    /// Determined by the pallet name.
    fn is_balance_display(&self) -> bool {
        PALLETS_BALANCE_VALID.contains(&self.pallet_name.as_str())
    }

    /// Transform `PalletSpecificData` into a set of flat formatted
    /// [`ExtendedCard`]s.
    fn card(
        &self,
        indent: u32,
        short_specs: &ShortSpecs,
        spec_name: &str,
        item: PalletSpecificItem,
    ) -> Vec<ExtendedCard> {
        let mut out = vec![ExtendedCard {
            parser_card: ParserCard::PalletName(self.pallet_name.to_owned()),
            indent,
            info_flat: vec![self.pallet_info.flatten()],
        }];

        let parser_card = match item {
            PalletSpecificItem::Call => ParserCard::CallName(self.variant_name.to_owned()),
            PalletSpecificItem::Event => ParserCard::EventName(self.variant_name.to_owned()),
        };
        out.push(ExtendedCard {
            parser_card,
            indent: indent + 1,
            info_flat: info_with_docs_only(&self.variant_docs),
        });

        if self.fields.len() == 1 && self.fields[0].field_name.is_none() {
            card_unnamed_single_field(
                &mut out,
                Vec::new(),
                &self.fields[0],
                indent + 2,
                self.is_balance_display(),
                short_specs,
                spec_name,
            );
        } else {
            card_field_set(
                &mut out,
                &self.fields,
                indent + 2,
                self.is_balance_display(),
                short_specs,
                spec_name,
            )
        }
        out
    }
}

impl Call {
    /// Transform `Call` into a set of flat formatted [`ExtendedCard`]s.
    pub fn card(
        &self,
        indent: u32,
        short_specs: &ShortSpecs,
        spec_name: &str,
    ) -> Vec<ExtendedCard> {
        self.0
            .card(indent, short_specs, spec_name, PalletSpecificItem::Call)
    }
}

impl Event {
    /// Transform `Event` into a set of flat formatted [`ExtendedCard`]s.
    pub fn card(
        &self,
        indent: u32,
        short_specs: &ShortSpecs,
        spec_name: &str,
    ) -> Vec<ExtendedCard> {
        self.0
            .card(indent, short_specs, spec_name, PalletSpecificItem::Event)
    }
}

/// Parsed data for a [`Field`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldData {
    pub field_name: Option<String>,
    pub type_name: Option<String>,
    pub field_docs: String,
    pub data: ExtendedData,
}

/// Parsed data for a [`Variant`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VariantData {
    pub variant_name: String,
    pub variant_docs: String,
    pub fields: Vec<FieldData>,
}

/// Parsed data for a sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceRawData {
    /// [`Info`] associated with every [`ParsedData`] in the sequence.
    pub element_info: Vec<Info>,

    /// [`ParsedData`] set. Note that all associated [`Info`] is in
    /// `element_info`.
    pub data: Vec<ParsedData>,
}

/// Parsed data for a wrapped sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceData {
    /// [`Info`] associated with every element of the [`Sequence`].
    pub element_info: Vec<Info>,

    /// `Vec<ParsedData>` wrapped into `Sequence`.
    pub data: Sequence,
}

/// Wrapped sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Sequence {
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    U64(Vec<u64>),
    U128(Vec<u128>),
    VecU8 {
        /// Sequence itself.
        sequence: Vec<Vec<u8>>,

        /// [`Info`] for individual `u8`.
        inner_element_info: Vec<Info>,
    },
}

/// Parsed data variants. As many types as possible are preserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedData {
    BitVecU8Lsb0(BitVec<u8, Lsb0>),
    BitVecU16Lsb0(BitVec<u16, Lsb0>),
    BitVecU32Lsb0(BitVec<u32, Lsb0>),
    #[cfg(target_pointer_width = "64")]
    BitVecU64Lsb0(BitVec<u64, Lsb0>),
    #[cfg(target_pointer_width = "32")]
    BitVecU64Lsb0(BitVec<u32, Lsb0>),
    BitVecU8Msb0(BitVec<u8, Msb0>),
    BitVecU16Msb0(BitVec<u16, Msb0>),
    BitVecU32Msb0(BitVec<u32, Msb0>),
    #[cfg(target_pointer_width = "64")]
    BitVecU64Msb0(BitVec<u64, Msb0>),
    #[cfg(target_pointer_width = "32")]
    BitVecU64Msb0(BitVec<u32, Msb0>),
    BlockHash(H256),
    Call(Call),
    Composite(Vec<FieldData>),
    EmptyVariant,
    Era(Era),
    Event(Event),
    GenesisHash(H256),
    H160(H160),
    H256(H256),
    H512(H512),
    Id(AccountId32),
    Option(Option<Box<ParsedData>>),
    PerU16(PerU16),
    Percent(Percent),
    Permill(Permill),
    Perbill(Perbill),
    Perquintill(Perquintill),
    PrimitiveBool(bool),
    PrimitiveChar(char),
    PrimitiveI8(i8),
    PrimitiveI16(i16),
    PrimitiveI32(i32),
    PrimitiveI64(i64),
    PrimitiveI128(i128),
    PrimitiveI256(BigInt),
    PrimitiveU8 {
        value: u8,
        specialty: SpecialtyUnsignedInteger,
    },
    PrimitiveU16 {
        value: u16,
        specialty: SpecialtyUnsignedInteger,
    },
    PrimitiveU32 {
        value: u32,
        specialty: SpecialtyUnsignedInteger,
    },
    PrimitiveU64 {
        value: u64,
        specialty: SpecialtyUnsignedInteger,
    },
    PrimitiveU128 {
        value: u128,
        specialty: SpecialtyUnsignedInteger,
    },
    PrimitiveU256(BigUint),
    PublicEd25519(PublicEd25519),
    PublicSr25519(PublicSr25519),
    PublicEcdsa(PublicEcdsa),
    Sequence(SequenceData),
    SequenceRaw(SequenceRawData),
    SignatureEd25519(SignatureEd25519),
    SignatureSr25519(SignatureSr25519),
    SignatureEcdsa(SignatureEcdsa),
    Text {
        text: String,
        specialty: SpecialtyStr,
    },
    Tuple(Vec<ExtendedData>),
    Variant(VariantData),
}

/// Transform [`ParsedData`] into single-element `Vec<ExtendedCard>`.
macro_rules! single_card {
    ($variant:ident, $value:tt, $indent:tt, $info_flat:tt) => {
        vec![ExtendedCard {
            parser_card: ParserCard::$variant($value.to_owned()),
            $indent,
            $info_flat,
        }]
    };
}

/// Transform [`ParsedData`] into single-element `Vec<ExtendedCard>` for types
/// supporting [`SpecialtyUnsignedInteger`].
macro_rules! specialty_card {
    ($ty:ty, $variant:ident, $value:tt, $display_balance:tt, $indent:tt, $info_flat:tt, $short_specs:tt, $specialty:tt, $spec_name:tt) => {
        vec![ExtendedCard {
            parser_card: match $specialty {
                SpecialtyUnsignedInteger::None => ParserCard::$variant($value.to_owned()),
                SpecialtyUnsignedInteger::Balance => {
                    if $display_balance {
                        let balance = <$ty>::convert_balance_pretty(
                            *$value,
                            $short_specs.decimals,
                            &$short_specs.unit,
                        );
                        ParserCard::Balance(balance)
                    } else {
                        ParserCard::BalanceRaw($value.to_string())
                    }
                }
                SpecialtyUnsignedInteger::Tip => {
                    let tip = <$ty>::convert_balance_pretty(
                        *$value,
                        $short_specs.decimals,
                        &$short_specs.unit,
                    );
                    ParserCard::Tip(tip)
                }
                SpecialtyUnsignedInteger::Nonce => ParserCard::Nonce($value.to_string()),
                SpecialtyUnsignedInteger::SpecVersion => ParserCard::NameSpecVersion {
                    name: $spec_name.to_owned(),
                    version: $value.to_string(),
                },
                SpecialtyUnsignedInteger::TxVersion => ParserCard::TxVersion($value.to_string()),
            },
            $indent,
            $info_flat,
        }]
    };
}

/// Transform [`Sequence`] into a vector of [`ExtendedCard`]s.
macro_rules! sequence {
    ($func:ident, $ty:ty, $variant:ident) => {
        /// Transform [`Sequence`] of `$ty` into a vector of [`ExtendedCard`]s.
        fn $func(
            set: &[$ty],
            indent: u32,
            info_flat: Vec<InfoFlat>,
            element_info_flat: Vec<InfoFlat>,
        ) -> Vec<ExtendedCard> {
            let mut out = vec![ExtendedCard {
                parser_card: ParserCard::SequenceAnnounced {
                    len: set.len(),
                    element_info_flat,
                },
                indent,
                info_flat,
            }];
            for element in set.iter() {
                out.push(ExtendedCard {
                    parser_card: ParserCard::$variant(*element),
                    indent: indent + 1,
                    info_flat: Vec::new(),
                })
            }
            out
        }
    };
}

sequence!(seq_u16, u16, PrimitiveU16);
sequence!(seq_u32, u32, PrimitiveU32);
sequence!(seq_u64, u64, PrimitiveU64);
sequence!(seq_u128, u128, PrimitiveU128);

impl ParsedData {
    /// Transform `ParsedData` into a set of flat formatted [`ExtendedCard`]s.
    pub fn card(
        &self,
        info_flat: Vec<InfoFlat>,
        indent: u32,
        display_balance: bool,
        short_specs: &ShortSpecs,
        spec_name: &str,
    ) -> Vec<ExtendedCard> {
        match &self {
            ParsedData::BitVecU8Lsb0(value) => single_card!(BitVecU8Lsb0, value, indent, info_flat),
            ParsedData::BitVecU16Lsb0(value) => {
                single_card!(BitVecU16Lsb0, value, indent, info_flat)
            }
            ParsedData::BitVecU32Lsb0(value) => {
                single_card!(BitVecU32Lsb0, value, indent, info_flat)
            }
            ParsedData::BitVecU64Lsb0(value) => {
                single_card!(BitVecU64Lsb0, value, indent, info_flat)
            }
            ParsedData::BitVecU8Msb0(value) => single_card!(BitVecU8Msb0, value, indent, info_flat),
            ParsedData::BitVecU16Msb0(value) => {
                single_card!(BitVecU16Msb0, value, indent, info_flat)
            }
            ParsedData::BitVecU32Msb0(value) => {
                single_card!(BitVecU32Msb0, value, indent, info_flat)
            }
            ParsedData::BitVecU64Msb0(value) => {
                single_card!(BitVecU64Msb0, value, indent, info_flat)
            }
            ParsedData::BlockHash(value) => single_card!(BlockHash, value, indent, info_flat),
            ParsedData::Call(call) => call.card(indent, short_specs, spec_name),
            ParsedData::Composite(field_data_set) => {
                if field_data_set.is_empty() {
                    Vec::new()
                } else if field_data_set.len() == 1 && field_data_set[0].field_name.is_none() {
                    let mut out = Vec::new();
                    card_unnamed_single_field(
                        &mut out,
                        info_flat,
                        &field_data_set[0],
                        indent,
                        display_balance,
                        short_specs,
                        spec_name,
                    );
                    out
                } else {
                    let mut out = vec![ExtendedCard {
                        parser_card: ParserCard::CompositeAnnounced(field_data_set.len()),
                        indent,
                        info_flat,
                    }];
                    card_field_set(
                        &mut out,
                        field_data_set,
                        indent + 1,
                        display_balance,
                        short_specs,
                        spec_name,
                    );
                    out
                }
            }
            ParsedData::EmptyVariant => Vec::new(),
            ParsedData::Era(value) => single_card!(Era, value, indent, info_flat),
            ParsedData::Event(event) => event.card(indent, short_specs, spec_name),
            ParsedData::GenesisHash(_) => Vec::new(),
            ParsedData::H160(value) => single_card!(H160, value, indent, info_flat),
            ParsedData::H256(value) => single_card!(H256, value, indent, info_flat),
            ParsedData::H512(value) => single_card!(H512, value, indent, info_flat),
            ParsedData::Id(value) => {
                vec![ExtendedCard {
                    parser_card: ParserCard::Id(IdData::from_account_id32(
                        value,
                        short_specs.base58prefix,
                    )),
                    indent,
                    info_flat,
                }]
            }
            ParsedData::Option(option) => match option {
                None => vec![ExtendedCard {
                    parser_card: ParserCard::None,
                    indent,
                    info_flat,
                }],
                Some(parsed_data) => {
                    parsed_data.card(info_flat, indent, display_balance, short_specs, spec_name)
                }
            },
            ParsedData::PerU16(value) => single_card!(PerU16, value, indent, info_flat),
            ParsedData::Percent(value) => single_card!(Percent, value, indent, info_flat),
            ParsedData::Permill(value) => single_card!(Permill, value, indent, info_flat),
            ParsedData::Perbill(value) => single_card!(Perbill, value, indent, info_flat),
            ParsedData::Perquintill(value) => single_card!(Perquintill, value, indent, info_flat),
            ParsedData::PrimitiveBool(value) => {
                single_card!(PrimitiveBool, value, indent, info_flat)
            }
            ParsedData::PrimitiveChar(value) => {
                single_card!(PrimitiveChar, value, indent, info_flat)
            }
            ParsedData::PrimitiveI8(value) => single_card!(PrimitiveI8, value, indent, info_flat),
            ParsedData::PrimitiveI16(value) => single_card!(PrimitiveI16, value, indent, info_flat),
            ParsedData::PrimitiveI32(value) => single_card!(PrimitiveI32, value, indent, info_flat),
            ParsedData::PrimitiveI64(value) => single_card!(PrimitiveI64, value, indent, info_flat),
            ParsedData::PrimitiveI128(value) => {
                single_card!(PrimitiveI128, value, indent, info_flat)
            }
            ParsedData::PrimitiveI256(value) => {
                single_card!(PrimitiveI256, value, indent, info_flat)
            }
            ParsedData::PrimitiveU8 { value, specialty } => specialty_card!(
                u8,
                PrimitiveU8,
                value,
                display_balance,
                indent,
                info_flat,
                short_specs,
                specialty,
                spec_name
            ),
            ParsedData::PrimitiveU16 { value, specialty } => specialty_card!(
                u16,
                PrimitiveU16,
                value,
                display_balance,
                indent,
                info_flat,
                short_specs,
                specialty,
                spec_name
            ),
            ParsedData::PrimitiveU32 { value, specialty } => specialty_card!(
                u32,
                PrimitiveU32,
                value,
                display_balance,
                indent,
                info_flat,
                short_specs,
                specialty,
                spec_name
            ),
            ParsedData::PrimitiveU64 { value, specialty } => specialty_card!(
                u64,
                PrimitiveU64,
                value,
                display_balance,
                indent,
                info_flat,
                short_specs,
                specialty,
                spec_name
            ),
            ParsedData::PrimitiveU128 { value, specialty } => specialty_card!(
                u128,
                PrimitiveU128,
                value,
                display_balance,
                indent,
                info_flat,
                short_specs,
                specialty,
                spec_name
            ),
            ParsedData::PrimitiveU256(value) => {
                single_card!(PrimitiveU256, value, indent, info_flat)
            }
            ParsedData::PublicEd25519(value) => {
                vec![ExtendedCard {
                    parser_card: ParserCard::PublicEd25519(IdData::from_public_ed25519(
                        value,
                        short_specs.base58prefix,
                    )),
                    indent,
                    info_flat,
                }]
            }
            ParsedData::PublicSr25519(value) => {
                vec![ExtendedCard {
                    parser_card: ParserCard::PublicSr25519(IdData::from_public_sr25519(
                        value,
                        short_specs.base58prefix,
                    )),
                    indent,
                    info_flat,
                }]
            }
            ParsedData::PublicEcdsa(value) => {
                vec![ExtendedCard {
                    parser_card: ParserCard::PublicEcdsa(IdData::from_public_ecdsa(
                        value,
                        short_specs.base58prefix,
                    )),
                    indent,
                    info_flat,
                }]
            }
            ParsedData::Sequence(sequence) => {
                let element_info_flat: Vec<InfoFlat> =
                    sequence.element_info.iter().map(|x| x.flatten()).collect();
                match &sequence.data {
                    Sequence::U8(vec) => {
                        let text = match String::from_utf8(vec.to_vec()) {
                            Ok(a) => Some(a),
                            Err(_) => None,
                        };
                        vec![ExtendedCard {
                            parser_card: ParserCard::SequenceU8 {
                                hex: hex::encode(vec),
                                text,
                                element_info_flat,
                            },
                            indent,
                            info_flat,
                        }]
                    }
                    Sequence::U16(vec) => seq_u16(vec, indent, info_flat, element_info_flat),
                    Sequence::U32(vec) => seq_u32(vec, indent, info_flat, element_info_flat),
                    Sequence::U64(vec) => seq_u64(vec, indent, info_flat, element_info_flat),
                    Sequence::U128(vec) => seq_u128(vec, indent, info_flat, element_info_flat),
                    Sequence::VecU8 {
                        sequence,
                        inner_element_info,
                    } => {
                        let mut out = vec![ExtendedCard {
                            parser_card: ParserCard::SequenceAnnounced {
                                len: sequence.len(),
                                element_info_flat,
                            },
                            indent,
                            info_flat,
                        }];
                        let inner_element_info_flat: Vec<InfoFlat> =
                            inner_element_info.iter().map(|x| x.flatten()).collect();
                        for element in sequence.iter() {
                            let text = match String::from_utf8(element.to_vec()) {
                                Ok(a) => Some(a),
                                Err(_) => None,
                            };
                            out.push(ExtendedCard {
                                parser_card: ParserCard::SequenceU8 {
                                    hex: hex::encode(element),
                                    text,
                                    element_info_flat: inner_element_info_flat.clone(),
                                },
                                indent: indent + 1,
                                info_flat: Vec::new(),
                            })
                        }
                        out
                    }
                }
            }
            ParsedData::SequenceRaw(sequence_raw) => {
                let element_info_flat: Vec<InfoFlat> = sequence_raw
                    .element_info
                    .iter()
                    .map(|x| x.flatten())
                    .collect();
                let mut out = vec![ExtendedCard {
                    parser_card: ParserCard::SequenceAnnounced {
                        len: sequence_raw.data.len(),
                        element_info_flat,
                    },
                    indent,
                    info_flat,
                }];
                for element in sequence_raw.data.iter() {
                    out.extend_from_slice(&element.card(
                        Vec::new(),
                        indent + 1,
                        display_balance,
                        short_specs,
                        spec_name,
                    ))
                }
                out
            }
            ParsedData::SignatureEd25519(value) => {
                single_card!(SignatureEd25519, value, indent, info_flat)
            }
            ParsedData::SignatureSr25519(value) => {
                single_card!(SignatureSr25519, value, indent, info_flat)
            }
            ParsedData::SignatureEcdsa(value) => {
                single_card!(SignatureEcdsa, value, indent, info_flat)
            }
            ParsedData::Text { text, specialty } => match specialty {
                SpecialtyStr::SpecName => single_card!(SpecName, text, indent, info_flat),
                SpecialtyStr::None => single_card!(Text, text, indent, info_flat),
            },
            ParsedData::Tuple(extended_data_set) => {
                if extended_data_set.is_empty() {
                    Vec::new()
                } else {
                    let mut out = vec![ExtendedCard {
                        parser_card: ParserCard::TupleAnnounced(extended_data_set.len()),
                        indent,
                        info_flat,
                    }];
                    for extended_data in extended_data_set.iter() {
                        out.extend_from_slice(&extended_data.card(
                            indent + 1,
                            display_balance,
                            short_specs,
                            spec_name,
                        ))
                    }
                    out
                }
            }
            ParsedData::Variant(variant_data) => {
                let mut out = vec![ExtendedCard {
                    parser_card: ParserCard::EnumAnnounced,
                    indent,
                    info_flat,
                }];
                out.push(ExtendedCard {
                    parser_card: ParserCard::EnumVariantName(variant_data.variant_name.to_owned()),
                    indent: indent + 1,
                    info_flat: info_with_docs_only(&variant_data.variant_docs),
                });
                if variant_data.fields.len() == 1 && variant_data.fields[0].field_name.is_none() {
                    card_unnamed_single_field(
                        &mut out,
                        Vec::new(),
                        &variant_data.fields[0],
                        indent + 2,
                        display_balance,
                        short_specs,
                        spec_name,
                    );
                } else {
                    card_field_set(
                        &mut out,
                        &variant_data.fields,
                        indent + 2,
                        display_balance,
                        short_specs,
                        spec_name,
                    )
                }
                out
            }
        }
    }
}

/// Card a single unnamed [`Field`] and add the card(s) into already existing
/// `Vec<ExtendedCard>`.
///
/// Single unnamed field is carded without `FieldNumber` card.
fn card_unnamed_single_field(
    out: &mut Vec<ExtendedCard>,
    mut new_info_flat: Vec<InfoFlat>,
    field_data: &FieldData,
    indent: u32,
    display_balance: bool,
    short_specs: &ShortSpecs,
    spec_name: &str,
) {
    if !field_data.field_docs.is_empty() {
        new_info_flat.push(InfoFlat {
            docs: Some(field_data.field_docs.to_owned()),
            path_flat: None,
        });
    }
    let inner_ty_info_flat: Vec<InfoFlat> =
        field_data.data.info.iter().map(|x| x.flatten()).collect();
    new_info_flat.extend_from_slice(&inner_ty_info_flat);
    out.extend_from_slice(&field_data.data.data.card(
        new_info_flat,
        indent,
        display_balance,
        short_specs,
        spec_name,
    ));
}

/// Card a set of [`Field`]s and add the cards into already existing
/// `Vec<ExtendedCard>`.
///
/// Named fields have associated `FieldName` card, unnamed fields have
/// associated `FieldNumber` card. It is not checked anywhere that the set
/// contains only named or only unnamed fields.
fn card_field_set(
    out: &mut Vec<ExtendedCard>,
    fields: &[FieldData],
    indent: u32,
    display_balance: bool,
    short_specs: &ShortSpecs,
    spec_name: &str,
) {
    for (i, field_data) in fields.iter().enumerate() {
        let parser_card = match field_data.field_name {
            Some(ref a) => ParserCard::FieldName(a.to_owned()),
            None => ParserCard::FieldNumber(i + 1),
        };
        out.push(ExtendedCard {
            parser_card,
            indent,
            info_flat: info_with_docs_only(&field_data.field_docs),
        });
        out.extend_from_slice(&field_data.data.card(
            indent + 1,
            display_balance,
            short_specs,
            spec_name,
        ));
    }
}

/// Produce `Vec<InfoFlat>` when there are only docs available.
///
/// For [`Field`], [`Variant`] and [`PalletSpecificItem`].
fn info_with_docs_only(docs: &str) -> Vec<InfoFlat> {
    if docs.is_empty() {
        Vec::new()
    } else {
        vec![InfoFlat {
            docs: Some(docs.to_owned()),
            path_flat: None,
        }]
    }
}

/// Helper for [`ExtendedCard`] display.
fn readable(indent: u32, card_type: &str, card_payload: &str) -> String {
    format!(
        "{}{}: {}",
        "  ".repeat(indent as usize),
        card_type,
        card_payload
    )
}

/// Formatted and flat decoded data, ready to be displayed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedCard {
    pub parser_card: ParserCard,
    pub indent: u32,
    pub info_flat: Vec<InfoFlat>,
}

/// Flat [`Type`] information.
///
/// At least one of the fields is non-`None`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfoFlat {
    pub docs: Option<String>,
    pub path_flat: Option<String>,
}

impl std::fmt::Display for InfoFlat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let docs_printed = self.docs.as_ref().map_or("None", |a| a);
        let path_printed = self.path_flat.as_ref().map_or("None", |a| a);
        write!(f, "(docs: {docs_printed}, path: {path_printed})")
    }
}

/// Id-associated data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdData {
    /// Base58 address
    #[cfg(any(feature = "std", feature = "embed-display"))]
    pub base58: String,

    /// Identicon `png` data
    #[cfg(feature = "std")]
    pub identicon: Vec<u8>,

    /// Hexadecimal key
    #[cfg(all(not(feature = "std"), not(feature = "embed-display")))]
    pub hex: String,
}

macro_rules! make_id_data {
    ($($func: ident, $ty: ty), *) => {
        $(
            impl IdData {
                #[cfg(feature = "std")]
                pub fn $func(value: &$ty, base58prefix: u16) -> Self {
                    let base58 = value.to_ss58check_with_version(Ss58AddressFormat::custom(base58prefix));
                    let identicon = generate_png_scaled_default(value.as_ref());
                    Self { base58, identicon }
                }
                #[cfg(feature = "embed-display")]
                pub fn $func(value: &$ty, base58prefix: u16) -> Self {
                    let base58 = value.as_base58(base58prefix);
                    Self { base58 }
                }
                #[cfg(all(not(feature = "std"), not(feature = "embed-display")))]
                pub fn $func(value: &$ty, _base58prefix: u16) -> Self {
                    Self { hex: hex::encode(value.0) }
                }
            }
        )*
    }
}

make_id_data!(from_account_id32, AccountId32);
make_id_data!(from_public_ed25519, PublicEd25519);
make_id_data!(from_public_sr25519, PublicSr25519);
make_id_data!(from_public_ecdsa, PublicEcdsa);

/// Flat cards content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParserCard {
    Balance(Currency),
    BalanceRaw(String),
    BitVecU8Lsb0(BitVec<u8, Lsb0>),
    BitVecU16Lsb0(BitVec<u16, Lsb0>),
    BitVecU32Lsb0(BitVec<u32, Lsb0>),
    #[cfg(target_pointer_width = "64")]
    BitVecU64Lsb0(BitVec<u64, Lsb0>),
    #[cfg(target_pointer_width = "32")]
    BitVecU64Lsb0(BitVec<u32, Lsb0>),
    BitVecU8Msb0(BitVec<u8, Msb0>),
    BitVecU16Msb0(BitVec<u16, Msb0>),
    BitVecU32Msb0(BitVec<u32, Msb0>),
    #[cfg(target_pointer_width = "64")]
    BitVecU64Msb0(BitVec<u64, Msb0>),
    #[cfg(target_pointer_width = "32")]
    BitVecU64Msb0(BitVec<u32, Msb0>),
    BlockHash(H256),
    CallName(String),
    CompositeAnnounced(usize),
    EnumAnnounced,
    EnumVariantName(String),
    Era(Era),
    EventName(String),
    FieldName(String),
    FieldNumber(usize),
    H160(H160),
    H256(H256),
    H512(H512),
    Id(IdData),
    NameSpecVersion {
        name: String,
        version: String,
    },
    Nonce(String),
    None,
    PalletName(String),
    PerU16(PerU16),
    Percent(Percent),
    Permill(Permill),
    Perbill(Perbill),
    Perquintill(Perquintill),
    PrimitiveBool(bool),
    PrimitiveChar(char),
    PrimitiveI8(i8),
    PrimitiveI16(i16),
    PrimitiveI32(i32),
    PrimitiveI64(i64),
    PrimitiveI128(i128),
    PrimitiveI256(BigInt),
    PrimitiveU8(u8),
    PrimitiveU16(u16),
    PrimitiveU32(u32),
    PrimitiveU64(u64),
    PrimitiveU128(u128),
    PrimitiveU256(BigUint),
    PublicEd25519(IdData),
    PublicSr25519(IdData),
    PublicEcdsa(IdData),
    SequenceAnnounced {
        len: usize,
        element_info_flat: Vec<InfoFlat>,
    },
    SequenceU8 {
        hex: String,
        text: Option<String>,
        element_info_flat: Vec<InfoFlat>,
    },
    SignatureEd25519(SignatureEd25519),
    SignatureSr25519(SignatureSr25519),
    SignatureEcdsa(SignatureEcdsa),
    SpecName(String),
    Text(String),
    Tip(Currency),
    TupleAnnounced(usize),
    TxVersion(String),
}

impl ExtendedData {
    /// Transform `ExtendedData` into a set of flat formatted [`ExtendedCard`]s.
    pub fn card(
        &self,
        indent: u32,
        display_balance: bool,
        short_specs: &ShortSpecs,
        spec_name: &str,
    ) -> Vec<ExtendedCard> {
        let info_flat = self.info.iter().map(|x| x.flatten()).collect();
        self.data
            .card(info_flat, indent, display_balance, short_specs, spec_name)
    }

    /// Display without associated type info.
    pub fn show(
        &self,
        indent: u32,
        display_balance: bool,
        short_specs: &ShortSpecs,
        spec_name: &str,
    ) -> String {
        let cards = self.card(indent, display_balance, short_specs, spec_name);
        cards
            .iter()
            .map(|a| a.show())
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Display with associated type info.
    pub fn show_with_docs(
        &self,
        indent: u32,
        display_balance: bool,
        short_specs: &ShortSpecs,
        spec_name: &str,
    ) -> String {
        let cards = self.card(indent, display_balance, short_specs, spec_name);
        cards
            .iter()
            .map(|a| a.show_with_docs())
            .collect::<Vec<String>>()
            .join("\n")
    }
}

impl ExtendedCard {
    /// Display without associated type info.
    pub fn show(&self) -> String {
        match &self.parser_card {
            ParserCard::Balance(a) => {
                readable(self.indent, "Balance", &format!("{} {}", a.number, a.units))
            }
            ParserCard::BalanceRaw(a) => readable(self.indent, "Balance Raw", a),
            ParserCard::BitVecU8Lsb0(a) => {
                readable(self.indent, "BitVec<u8, Lsb0>", &a.to_string())
            }
            ParserCard::BitVecU16Lsb0(a) => {
                readable(self.indent, "BitVec<u16, Lsb0>", &a.to_string())
            }
            ParserCard::BitVecU32Lsb0(a) => {
                readable(self.indent, "BitVec<u32, Lsb0>", &a.to_string())
            }
            ParserCard::BitVecU64Lsb0(a) => {
                readable(self.indent, "BitVec<u64, Lsb0>", &a.to_string())
            }
            ParserCard::BitVecU8Msb0(a) => {
                readable(self.indent, "BitVec<u8, Msb0>", &a.to_string())
            }
            ParserCard::BitVecU16Msb0(a) => {
                readable(self.indent, "BitVec<u16, Msb0>", &a.to_string())
            }
            ParserCard::BitVecU32Msb0(a) => {
                readable(self.indent, "BitVec<u32, Msb0>", &a.to_string())
            }
            ParserCard::BitVecU64Msb0(a) => {
                readable(self.indent, "BitVec<u64, Msb0>", &a.to_string())
            }
            ParserCard::BlockHash(a) => readable(self.indent, "Block Hash", &hex::encode(a)),
            ParserCard::CallName(a) => readable(self.indent, "Call", a),
            ParserCard::CompositeAnnounced(a) => {
                readable(self.indent, "Struct", &format!("{a} field(s)"))
            }
            ParserCard::EnumAnnounced => format!("{}Enum", "  ".repeat(self.indent as usize)),
            ParserCard::EnumVariantName(a) => readable(self.indent, "Enum Variant Name", a),
            ParserCard::Era(a) => match a {
                Era::Immortal => readable(self.indent, "Era", "Immortal"),
                Era::Mortal(period, phase) => readable(
                    self.indent,
                    "Era",
                    &format!("Mortal, phase: {phase}, period: {period}"),
                ),
            },
            ParserCard::EventName(a) => readable(self.indent, "Event", a),
            ParserCard::FieldName(a) => readable(self.indent, "Field Name", a),
            ParserCard::FieldNumber(a) => readable(self.indent, "Field Number", &a.to_string()),
            ParserCard::H160(a) => readable(self.indent, "H160", &hex::encode(a.0)),
            ParserCard::H256(a) => readable(self.indent, "H256", &hex::encode(a.0)),
            ParserCard::H512(a) => readable(self.indent, "H512", &hex::encode(a.0)),
            #[cfg(any(feature = "std", feature = "embed-display"))]
            ParserCard::Id(a) => readable(self.indent, "Id", &a.base58),
            #[cfg(all(not(feature = "std"), not(feature = "embed-display")))]
            ParserCard::Id(a) => readable(self.indent, "Id", &a.hex),
            ParserCard::NameSpecVersion { name, version } => {
                readable(self.indent, "Chain", &format!("{name}{version}"))
            }
            ParserCard::Nonce(a) => readable(self.indent, "Nonce", a),
            ParserCard::None => readable(self.indent, "Option", "None"),
            ParserCard::PalletName(a) => readable(self.indent, "Pallet", a),
            ParserCard::PerU16(a) => readable(self.indent, "PerU16", &a.deconstruct().to_string()),
            ParserCard::Percent(a) => {
                readable(self.indent, "Percent", &a.deconstruct().to_string())
            }
            ParserCard::Permill(a) => {
                readable(self.indent, "Permill", &a.deconstruct().to_string())
            }
            ParserCard::Perbill(a) => {
                readable(self.indent, "Perbill", &a.deconstruct().to_string())
            }
            ParserCard::Perquintill(a) => {
                readable(self.indent, "Perquintill", &a.deconstruct().to_string())
            }
            ParserCard::PrimitiveBool(a) => readable(self.indent, "Bool", &a.to_string()),
            ParserCard::PrimitiveChar(a) => readable(self.indent, "Char", &a.to_string()),
            ParserCard::PrimitiveI8(a) => readable(self.indent, "i8", &a.to_string()),
            ParserCard::PrimitiveI16(a) => readable(self.indent, "i16", &a.to_string()),
            ParserCard::PrimitiveI32(a) => readable(self.indent, "i32", &a.to_string()),
            ParserCard::PrimitiveI64(a) => readable(self.indent, "i64", &a.to_string()),
            ParserCard::PrimitiveI128(a) => readable(self.indent, "i128", &a.to_string()),
            ParserCard::PrimitiveI256(a) => readable(self.indent, "BigInt", &a.to_string()),
            ParserCard::PrimitiveU8(a) => readable(self.indent, "u8", &a.to_string()),
            ParserCard::PrimitiveU16(a) => readable(self.indent, "u16", &a.to_string()),
            ParserCard::PrimitiveU32(a) => readable(self.indent, "u32", &a.to_string()),
            ParserCard::PrimitiveU64(a) => readable(self.indent, "u64", &a.to_string()),
            ParserCard::PrimitiveU128(a) => readable(self.indent, "u128", &a.to_string()),
            ParserCard::PrimitiveU256(a) => readable(self.indent, "BigUint", &a.to_string()),
            #[cfg(any(feature = "std", feature = "embed-display"))]
            ParserCard::PublicEd25519(a) => readable(self.indent, "PublicKey Ed25519", &a.base58),
            #[cfg(all(not(feature = "std"), not(feature = "embed-display")))]
            ParserCard::PublicEd25519(a) => readable(self.indent, "PublicKey Ed25519", &a.hex),
            #[cfg(any(feature = "std", feature = "embed-display"))]
            ParserCard::PublicSr25519(a) => readable(self.indent, "PublicKey Sr25519", &a.base58),
            #[cfg(all(not(feature = "std"), not(feature = "embed-display")))]
            ParserCard::PublicSr25519(a) => readable(self.indent, "PublicKey Sr25519", &a.hex),
            #[cfg(any(feature = "std", feature = "embed-display"))]
            ParserCard::PublicEcdsa(a) => readable(self.indent, "PublicKey Ecdsa", &a.base58),
            #[cfg(all(not(feature = "std"), not(feature = "embed-display")))]
            ParserCard::PublicEcdsa(a) => readable(self.indent, "PublicKey Ecdsa", &a.hex),
            ParserCard::SequenceAnnounced {
                len,
                element_info_flat: _,
            } => readable(self.indent, "Sequence", &format!("{len} element(s)")),
            ParserCard::SequenceU8 {
                hex,
                text,
                element_info_flat: _,
            } => match text {
                Some(valid_text) => readable(self.indent, "Text", valid_text),
                None => readable(self.indent, "Sequence u8", hex),
            },
            ParserCard::SignatureEd25519(a) => {
                readable(self.indent, "Signature Ed25519", &hex::encode(a.0))
            }
            ParserCard::SignatureSr25519(a) => {
                readable(self.indent, "Signature Sr25519", &hex::encode(a.0))
            }
            ParserCard::SignatureEcdsa(a) => {
                readable(self.indent, "Signature Ecdsa", &hex::encode(a.0))
            }
            ParserCard::SpecName(a) => readable(self.indent, "Spec Name", a),
            ParserCard::Text(a) => readable(self.indent, "Text", a),
            ParserCard::Tip(a) => {
                readable(self.indent, "Tip", &format!("{} {}", a.number, a.units))
            }
            ParserCard::TupleAnnounced(a) => {
                readable(self.indent, "Tuple", &format!("{a} element(s)"))
            }
            ParserCard::TxVersion(a) => readable(self.indent, "Tx Version", a),
        }
    }

    /// Display with associated type info.
    pub fn show_with_docs(&self) -> String {
        let mut info_printed = String::new();
        for info_flat in self.info_flat.iter() {
            let _ = write!(
                info_printed,
                "\n{}{}",
                "  ".repeat(self.indent as usize),
                info_flat
            );
        }
        let card_printed = match &self.parser_card {
            ParserCard::SequenceAnnounced {
                len,
                element_info_flat,
            } => {
                let element_info_printed = element_info_flat
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                if element_info_printed.is_empty() {
                    readable(self.indent, "Sequence", &format!("{len} element(s)"))
                } else {
                    readable(
                        self.indent,
                        "Sequence",
                        &format!("{len} element(s), element info: [{element_info_printed}]"),
                    )
                }
            }
            ParserCard::SequenceU8 {
                hex,
                text,
                element_info_flat,
            } => {
                let element_info_printed = element_info_flat
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                if element_info_printed.is_empty() {
                    match text {
                        Some(valid_text) => readable(self.indent, "Text", valid_text),
                        None => readable(self.indent, "Sequence u8", hex),
                    }
                } else {
                    match text {
                        Some(valid_text) => readable(
                            self.indent,
                            "Text",
                            &format!("{valid_text}, element info: [{element_info_printed}]"),
                        ),
                        None => readable(
                            self.indent,
                            "Sequence u8",
                            &format!("{hex}, element info: [{element_info_printed}]"),
                        ),
                    }
                }
            }
            _ => self.show(),
        };
        format!("{card_printed}{info_printed}")
    }
}
