//! Parsed cards to display decoded call and extensions data
use bitvec::prelude::{BitVec, Lsb0, Msb0};
use num_bigint::{BigInt, BigUint};
use scale_info::{form::PortableForm, Field, Path, Type, Variant};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};
use sp_core::{
    crypto::{AccountId32, Ss58AddressFormat, Ss58Codec},
    ecdsa, ed25519, sr25519, H160, H256, H512,
};
use sp_runtime::generic::Era;

use crate::printing_balance::{AsBalance, Currency};
use crate::special_indicators::{PalletSpecificItem, SpecialtyPrimitive};
use crate::special_types::StLenCheckSpecialtyCompact;
use crate::ShortSpecs;

#[derive(Clone, Debug)]
pub struct Info {
    pub docs: String,
    pub path: Path<PortableForm>,
}

impl Info {
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty() && self.path.is_empty()
    }
    pub fn from_ty(ty: &Type<PortableForm>) -> Self {
        Self {
            docs: ty.collect_docs(),
            path: ty.path().to_owned(),
        }
    }
    pub fn flatten(&self) -> InfoFlat {
        let mut path_flat = String::new();
        for (i, x) in self.path.segments().iter().enumerate() {
            if i > 0 {
                path_flat.push_str(" >> ");
            }
            path_flat.push_str(x);
        }
        InfoFlat{
            docs: self.docs.to_owned(),
            path_flat,
        }
    }
}

pub trait Documented {
    fn collect_docs(&self) -> String;
}

macro_rules! impl_documented {
    ($($ty: ty), *) => {
        $(
            impl Documented for $ty {
                fn collect_docs(&self) -> String {
                    let mut docs = String::new();
                    for (i, docs_line) in self.docs().iter().enumerate() {
                        if i > 0 {docs.push('\n')}
                        docs.push_str(docs_line);
                    }
                    docs
                }
            }
        )*
    }
}

impl_documented!(
    Type<PortableForm>,
    Field<PortableForm>,
    Variant<PortableForm>
);

/// Each decoding results in `ExtendedData`
#[derive(Clone, Debug)]
pub struct ExtendedData {
    pub info: Vec<Info>,
    pub data: ParsedData,
}

#[derive(Clone, Debug)]
pub struct PalletSpecificData {
    pub pallet_info: Info,
    pub variant_docs: String,
    pub pallet_name: String,
    pub variant_name: String,
    pub fields: Vec<FieldData>,
}

#[derive(Clone, Debug)]
pub struct Call(pub PalletSpecificData);

#[derive(Clone, Debug)]
pub struct Event(pub PalletSpecificData);

impl PalletSpecificData {
    fn is_balance_display(&self) -> bool {
        self.pallet_name == "Balances" || self.pallet_name == "Staking"
    }
    fn card(&self, indent: u32, short_specs: &ShortSpecs, item: PalletSpecificItem) -> Vec<ExtendedCard> {
        let mut out = vec![ExtendedCard{
            parser_card: ParserCard::PalletName(self.pallet_name.to_owned()),
            indent,
            info_flat: vec![self.pallet_info.flatten()],
        }];

        let parser_card = match item {
            PalletSpecificItem::Call => ParserCard::CallName(self.variant_name.to_owned()),
            PalletSpecificItem::Event => ParserCard::EventName(self.variant_name.to_owned()),
        };
        out.push(ExtendedCard{
            parser_card,
            indent: indent+1,
            info_flat: vec![InfoFlat{
                docs: self.variant_docs.to_owned(),
                path_flat: String::new(),
            }]
        });

        for (i, field_data) in self.fields.iter().enumerate() {
            let parser_card = match field_data.field_name {
                Some(ref a) => ParserCard::FieldName(a.to_owned()),
                None => ParserCard::FieldNumber(i.to_string()),
            };
            out.push(ExtendedCard{
                parser_card,
                indent: indent+2,
                info_flat: vec![InfoFlat{
                    docs: field_data.field_docs.to_owned(),
                    path_flat: String::new(),
                }]
            });
            
            out.extend_from_slice(&field_data.data.card(indent+3, self.is_balance_display(), short_specs));
        }
        out
    }
    fn show(&self, indent: u32, short_specs: &ShortSpecs, item: PalletSpecificItem) -> String {
        let identifier = match item {
            PalletSpecificItem::Call => "call",
            PalletSpecificItem::Event => "event",
        };
        let mut out = [
            readable(indent, "pallet", &self.pallet_name),
            String::from("\n"),
            readable(indent + 1, identifier, &self.variant_name),
        ]
        .concat();
        for (i, field_data) in self.fields.iter().enumerate() {
            out.push('\n');
            match field_data.field_name {
                Some(ref a) => out.push_str(&readable(indent + 2, "field_name", a)),
                None => out.push_str(&readable(indent + 2, "field_number", &i.to_string())),
            }
            out.push('\n');
            out.push_str(&field_data.data.data.show(
                indent + 3,
                short_specs,
                self.is_balance_display(),
            ))
        }
        out
    }
}

impl Call {
    pub fn show(&self, indent: u32, short_specs: &ShortSpecs) -> String {
        self.0.show(indent, short_specs, PalletSpecificItem::Call)
    }
    pub fn card(&self, indent: u32, short_specs: &ShortSpecs) -> Vec<ExtendedCard> {
        self.0.card(indent, short_specs, PalletSpecificItem::Call)
    }
}

impl Event {
    pub fn show(&self, indent: u32, short_specs: &ShortSpecs) -> String {
        self.0.show(indent, short_specs, PalletSpecificItem::Event)
    }
    pub fn card(&self, indent: u32, short_specs: &ShortSpecs) -> Vec<ExtendedCard> {
        self.0.card(indent, short_specs, PalletSpecificItem::Event)
    }
}

#[derive(Clone, Debug)]
pub struct FieldData {
    pub field_name: Option<String>,
    pub type_name: Option<String>,
    pub field_docs: String,
    pub data: ExtendedData,
}

#[derive(Clone, Debug)]
pub struct VariantData {
    pub variant_name: String,
    pub variant_docs: String,
    pub fields: Vec<FieldData>,
}

/// For both vectors and arrays
#[derive(Clone, Debug)]
pub struct SequenceRawData {
    pub info: Vec<Info>, // info associated with every `ParsedData`
    pub data: Vec<ParsedData>,
}

/// For both vectors and arrays
#[derive(Clone, Debug)]
pub struct SequenceData {
    pub info: Vec<Info>, // info associated with every `ParsedData`
    pub data: Sequence,
}

#[derive(Clone, Debug)]
pub enum Sequence {
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    U64(Vec<u64>),
    U128(Vec<u128>),
    VecU8(Vec<Vec<u8>>), // assumed here that no reasonably needed info is ever accompanying each u8 element
}

impl Sequence {
    fn show(&self, indent: u32) -> String {
        match &self {
            Sequence::U8(a) => readable(indent, "sequence u8", &hex::encode(a)),
            Sequence::U16(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push('\n')
                    }
                    out.push_str(&readable(indent, "u16", &x.to_string()));
                }
                out
            }
            Sequence::U32(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push('\n')
                    }
                    out.push_str(&readable(indent, "u32", &x.to_string()));
                }
                out
            }
            Sequence::U64(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push('\n')
                    }
                    out.push_str(&readable(indent, "u64", &x.to_string()));
                }
                out
            }
            Sequence::U128(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push('\n')
                    }
                    out.push_str(&readable(indent, "u128", &x.to_string()));
                }
                out
            }
            Sequence::VecU8(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push('\n')
                    }
                    out.push_str(&readable(indent, "sequence u8", &hex::encode(x)));
                }
                out
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum ParsedData {
    BitVecU8Lsb0(BitVec<u8, Lsb0>),
    BitVecU16Lsb0(BitVec<u16, Lsb0>),
    BitVecU32Lsb0(BitVec<u32, Lsb0>),
    BitVecU64Lsb0(BitVec<u64, Lsb0>),
    BitVecU8Msb0(BitVec<u8, Msb0>),
    BitVecU16Msb0(BitVec<u16, Msb0>),
    BitVecU32Msb0(BitVec<u32, Msb0>),
    BitVecU64Msb0(BitVec<u64, Msb0>),
    BlockHash(H256),
    Call(Call),
    Composite(Vec<FieldData>),
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
        specialty: SpecialtyPrimitive,
    },
    PrimitiveU16 {
        value: u16,
        specialty: SpecialtyPrimitive,
    },
    PrimitiveU32 {
        value: u32,
        specialty: SpecialtyPrimitive,
    },
    PrimitiveU64 {
        value: u64,
        specialty: SpecialtyPrimitive,
    },
    PrimitiveU128 {
        value: u128,
        specialty: SpecialtyPrimitive,
    },
    PrimitiveU256(BigUint),
    PublicEd25519(ed25519::Public),
    PublicSr25519(sr25519::Public),
    PublicEcdsa(ecdsa::Public),
    Sequence(SequenceData),
    SequenceRaw(SequenceRawData),
    SignatureEd25519(ed25519::Signature),
    SignatureSr25519(sr25519::Signature),
    SignatureEcdsa(ecdsa::Signature),
    Text(String),
    Tuple(Vec<ExtendedData>),
    Variant(VariantData),
}

macro_rules! single_card {
    ($variant:ident, $value:tt, $indent:tt, $info_flat:tt) => {
        vec![ExtendedCard{
            parser_card: ParserCard::$variant($value.to_owned()),
            $indent,
            $info_flat,
        }]
    }
}

macro_rules! specialty_card {
    ($ty:ty, $variant:ident, $value:tt, $display_balance:tt, $indent:tt, $info_flat:tt, $short_specs:tt, $specialty:tt) => {
        vec![ExtendedCard{
            parser_card: match $specialty {
            SpecialtyPrimitive::None => ParserCard::$variant($value.to_owned()),
            SpecialtyPrimitive::Balance => {
                if $display_balance {
                    let balance = <$ty>::convert_balance_pretty(*$value, $short_specs.decimals, &$short_specs.unit);
                    ParserCard::Balance(balance)
                } else {
                    ParserCard::BalanceRaw($value.to_string())
                }
            },
            SpecialtyPrimitive::Tip => {
                let tip = <$ty>::convert_balance_pretty(*$value, $short_specs.decimals, &$short_specs.unit);
                ParserCard::Tip(tip)
            },
            SpecialtyPrimitive::Nonce => ParserCard::Nonce($value.to_string()),
            SpecialtyPrimitive::SpecVersion => ParserCard::NameSpecVersion { name: $short_specs.name.to_owned(), version: $value.to_string() },
            SpecialtyPrimitive::TxVersion => ParserCard::TxVersion($value.to_string()),
        },
            $indent,
            $info_flat,
        }]
    }
}

macro_rules! sequence {
    ($func:ident, $ty:ty, $variant:ident) => {
        fn $func(set: &[$ty], indent: u32, info_flat: Vec<InfoFlat>) -> Vec<ExtendedCard> {
            let mut out = vec![ExtendedCard{
                parser_card: ParserCard::SequenceAnnounced,
                indent,
                info_flat,
            }];
            for element in set.iter() {
                out.push(ExtendedCard{
                    parser_card: ParserCard::$variant(*element),
                    indent: indent+1,
                    info_flat: Vec::new(),
                })
            }
            out
        }
    }
}

sequence!(seq_u16, u16, PrimitiveU16);
sequence!(seq_u32, u32, PrimitiveU32);
sequence!(seq_u64, u64, PrimitiveU64);
sequence!(seq_u128, u128, PrimitiveU128);

impl ParsedData {
    pub fn card(&self, info_flat: Vec<InfoFlat>, indent: u32, display_balance: bool, short_specs: &ShortSpecs) -> Vec<ExtendedCard> {
        match &self {
            ParsedData::BitVecU8Lsb0(value) => single_card!(BitVecU8Lsb0, value, indent, info_flat),
            ParsedData::BitVecU16Lsb0(value) => single_card!(BitVecU16Lsb0, value, indent, info_flat),
            ParsedData::BitVecU32Lsb0(value) => single_card!(BitVecU32Lsb0, value, indent, info_flat),
            ParsedData::BitVecU64Lsb0(value) => single_card!(BitVecU64Lsb0, value, indent, info_flat),
            ParsedData::BitVecU8Msb0(value) => single_card!(BitVecU8Msb0, value, indent, info_flat),
            ParsedData::BitVecU16Msb0(value) => single_card!(BitVecU16Msb0, value, indent, info_flat),
            ParsedData::BitVecU32Msb0(value) => single_card!(BitVecU32Msb0, value, indent, info_flat),
            ParsedData::BitVecU64Msb0(value) => single_card!(BitVecU64Msb0, value, indent, info_flat),
            ParsedData::BlockHash(value) => single_card!(BlockHash, value, indent, info_flat),
            ParsedData::Call(call) => call.card(indent, short_specs),
            ParsedData::Composite(field_data_set) => {
                if (field_data_set.len() == 1) && (field_data_set[0].field_name.is_none()) {
                    let mut new_info_flat = info_flat;
                    let field_info_flat: Vec<InfoFlat> = field_data_set[0].data.info.iter().map(|x| x.flatten()).collect();
                    new_info_flat.extend_from_slice(&field_info_flat);
                    field_data_set[0]
                        .data
                        .data
                        .card(new_info_flat, indent, display_balance, short_specs)
                } else {
                    let mut out: Vec<ExtendedCard> = Vec::new();
                    for (i, field_data) in field_data_set.iter().enumerate() {
                        let parser_card = match field_data.field_name {
                            Some(ref a) => ParserCard::FieldName(a.to_owned()),
                            None => ParserCard::FieldNumber(i.to_string()),
                        };
                        out.push(ExtendedCard{
                            parser_card,
                            indent,
                            info_flat: vec![InfoFlat{
                                docs: field_data.field_docs.to_owned(),
                                path_flat: String::new(),
                            }]
                        });
            
                        out.extend_from_slice(&field_data.data.card(indent+1, display_balance, short_specs));
                    }
                    out
                }
            },
            ParsedData::Era(value) => single_card!(Era, value, indent, info_flat),
            ParsedData::Event(event) => event.card(indent, short_specs),
            ParsedData::GenesisHash(value) => single_card!(GenesisHash, value, indent, info_flat),
            ParsedData::H160(value) => single_card!(H160, value, indent, info_flat),
            ParsedData::H256(value) => single_card!(H256, value, indent, info_flat),
            ParsedData::H512(value) => single_card!(H512, value, indent, info_flat),
            ParsedData::Id(value) => single_card!(Id, value, indent, info_flat),
            ParsedData::Option(option) => match option {
                None => vec![ExtendedCard{
                    parser_card: ParserCard::None,
                    indent,
                    info_flat,
                }],
                Some(parsed_data) => parsed_data.card(info_flat, indent, display_balance, short_specs)
            },
            ParsedData::PerU16(value) => single_card!(PerU16, value, indent, info_flat),
            ParsedData::Percent(value) => single_card!(Percent, value, indent, info_flat),
            ParsedData::Permill(value) => single_card!(Permill, value, indent, info_flat),
            ParsedData::Perbill(value) => single_card!(Perbill, value, indent, info_flat),
            ParsedData::Perquintill(value) => single_card!(Perquintill, value, indent, info_flat),
            ParsedData::PrimitiveBool(value) => single_card!(PrimitiveBool, value, indent, info_flat),
            ParsedData::PrimitiveChar(value) => single_card!(PrimitiveChar, value, indent, info_flat),
            ParsedData::PrimitiveI8(value) => single_card!(PrimitiveI8, value, indent, info_flat),
            ParsedData::PrimitiveI16(value) => single_card!(PrimitiveI16, value, indent, info_flat),
            ParsedData::PrimitiveI32(value) => single_card!(PrimitiveI32, value, indent, info_flat),
            ParsedData::PrimitiveI64(value) => single_card!(PrimitiveI64, value, indent, info_flat),
            ParsedData::PrimitiveI128(value) => single_card!(PrimitiveI128, value, indent, info_flat),
            ParsedData::PrimitiveI256(value) => single_card!(PrimitiveI256, value, indent, info_flat),
            ParsedData::PrimitiveU8 { value, specialty } => 
                specialty_card!(u8, PrimitiveU8, value, display_balance, indent, info_flat, short_specs, specialty),
            ParsedData::PrimitiveU16 { value, specialty } => 
                specialty_card!(u16, PrimitiveU16, value, display_balance, indent, info_flat, short_specs, specialty),
            ParsedData::PrimitiveU32 { value, specialty } => 
                specialty_card!(u32, PrimitiveU32, value, display_balance, indent, info_flat, short_specs, specialty),
            ParsedData::PrimitiveU64 { value, specialty } => 
                specialty_card!(u64, PrimitiveU64, value, display_balance, indent, info_flat, short_specs, specialty),
            ParsedData::PrimitiveU128 { value, specialty } => 
                specialty_card!(u128, PrimitiveU128, value, display_balance, indent, info_flat, short_specs, specialty),
            ParsedData::PrimitiveU256(value) => single_card!(PrimitiveU256, value, indent, info_flat),
            ParsedData::PublicEd25519(value) => single_card!(PublicEd25519, value, indent, info_flat),
            ParsedData::PublicSr25519(value) => single_card!(PublicSr25519, value, indent, info_flat),
            ParsedData::PublicEcdsa(value) => single_card!(PublicEcdsa, value, indent, info_flat),
            ParsedData::Sequence(sequence) => {
                let mut new_info_flat = info_flat;
                let sequence_info_flat: Vec<InfoFlat> = sequence.info.iter().map(|x| x.flatten()).collect();
                new_info_flat.extend_from_slice(&sequence_info_flat);
                match &sequence.data {
                    Sequence::U8(vec) => {
                        let text = match String::from_utf8(vec.to_vec()) {
                            Ok(a) => Some(a),
                            Err(_) => None,
                        };
                        vec![ExtendedCard{
                            parser_card: ParserCard::SequenceU8{hex: hex::encode(vec), text},
                            indent,
                            info_flat: new_info_flat,
                        }]
                    },
                    Sequence::U16(vec) => seq_u16(vec, indent, new_info_flat),
                    Sequence::U32(vec) => seq_u32(vec, indent, new_info_flat),
                    Sequence::U64(vec) => seq_u64(vec, indent, new_info_flat),
                    Sequence::U128(vec) => seq_u128(vec, indent, new_info_flat),
                    Sequence::VecU8(vec) => {
                        let mut out = vec![ExtendedCard{
                            parser_card: ParserCard::SequenceAnnounced,
                            indent,
                            info_flat: new_info_flat,
                        }];
                        for element in vec.iter() {
                            let text = match String::from_utf8(element.to_vec()) {
                                Ok(a) => Some(a),
                                Err(_) => None,
                            };
                            out.push(ExtendedCard{
                                parser_card: ParserCard::SequenceU8{hex: hex::encode(element), text},
                                indent: indent+1,
                                info_flat: Vec::new(),
                            })
                        }
                        out
                    },
                }
            },
            ParsedData::SequenceRaw(sequence_raw) => {
                let mut new_info_flat = info_flat;
                let sequence_info_flat: Vec<InfoFlat> = sequence_raw.info.iter().map(|x| x.flatten()).collect();
                new_info_flat.extend_from_slice(&sequence_info_flat);
                let mut out = vec![ExtendedCard{
                    parser_card: ParserCard::SequenceAnnounced,
                    indent,
                    info_flat: new_info_flat,
                }];
                for element in sequence_raw.data.iter() {
                    out.extend_from_slice(&element.card(Vec::new(), indent, display_balance, short_specs))
                }
                out
            },
            ParsedData::SignatureEd25519(value) => single_card!(SignatureEd25519, value, indent, info_flat),
            ParsedData::SignatureSr25519(value) => single_card!(SignatureSr25519, value, indent, info_flat),
            ParsedData::SignatureEcdsa(value) => single_card!(SignatureEcdsa, value, indent, info_flat),
            ParsedData::Text(value) => single_card!(Text, value, indent, info_flat),
            ParsedData::Tuple(extended_data_set) => {
                let mut out: Vec<ExtendedCard> = Vec::new();
                for extended_data in extended_data_set.iter() {
                    out.extend_from_slice(&extended_data.card(indent, display_balance, short_specs))
                }
                out
            }, 
            ParsedData::Variant(variant_data) => {
                let mut new_info_flat = info_flat;
                new_info_flat.push(InfoFlat{
                    docs: variant_data.variant_docs.to_owned(),
                    path_flat: String::new(),
                });
                let mut out = vec![ExtendedCard{
                    parser_card: ParserCard::EnumVariantName(variant_data.variant_name.to_owned()),
                    indent,
                    info_flat: new_info_flat,
                }];
                
                if (variant_data.fields.len() == 1) && (variant_data.fields[0].field_name.is_none()) {
                    out.extend_from_slice(&variant_data.fields[0]
                        .data
                        .card(indent+1, display_balance, short_specs))
                } else {
                    for (i, field_data) in variant_data.fields.iter().enumerate() {
                        let parser_card = match field_data.field_name {
                            Some(ref a) => ParserCard::FieldName(a.to_owned()),
                            None => ParserCard::FieldNumber(i.to_string()),
                        };
                        out.push(ExtendedCard{
                            parser_card,
                            indent: indent+1,
                            info_flat: vec![InfoFlat{
                                docs: field_data.field_docs.to_owned(),
                                path_flat: String::new(),
                            }]
                        });
            
                        out.extend_from_slice(&field_data.data.card(indent+2, display_balance, short_specs));
                    }
                }
                out
            },
        }
    }

    pub fn show(&self, indent: u32, short_specs: &ShortSpecs, display_balance: bool) -> String {
        match &self {
            ParsedData::BitVecU8Lsb0(a) => readable(indent, "BitVec<u8, Lsb0>", &a.to_string()),
            ParsedData::BitVecU16Lsb0(a) => readable(indent, "BitVec<u16, Lsb0>", &a.to_string()),
            ParsedData::BitVecU32Lsb0(a) => readable(indent, "BitVec<u32, Lsb0>", &a.to_string()),
            ParsedData::BitVecU64Lsb0(a) => readable(indent, "BitVec<u64, Lsb0>", &a.to_string()),
            ParsedData::BitVecU8Msb0(a) => readable(indent, "BitVec<u8, Msb0>", &a.to_string()),
            ParsedData::BitVecU16Msb0(a) => readable(indent, "BitVec<u16, Msb0>", &a.to_string()),
            ParsedData::BitVecU32Msb0(a) => readable(indent, "BitVec<u32, Msb0>", &a.to_string()),
            ParsedData::BitVecU64Msb0(a) => readable(indent, "BitVec<u64, Msb0>", &a.to_string()),
            ParsedData::BlockHash(block_hash) => {
                readable(indent, "block_hash", &hex::encode(block_hash))
            }
            ParsedData::Call(call) => call.show(indent, short_specs),
            ParsedData::Composite(field_data_set) => {
                if (field_data_set.len() == 1) && (field_data_set[0].field_name.is_none()) {
                    field_data_set[0]
                        .data
                        .data
                        .show(indent, short_specs, display_balance)
                } else {
                    let mut out = String::new();
                    for (i, field_data) in field_data_set.iter().enumerate() {
                        if i > 0 {
                            out.push('\n')
                        }
                        match field_data.field_name {
                            Some(ref a) => out.push_str(&readable(indent, "field_name", a)),
                            None => out.push_str(&readable(indent, "field_number", &i.to_string())),
                        }
                        out.push('\n');
                        out.push_str(&field_data.data.data.show(
                            indent + 1,
                            short_specs,
                            display_balance,
                        ))
                    }
                    out
                }
            }
            ParsedData::Era(era) => match era {
                Era::Immortal => readable(indent, "era", "Immortal"),
                Era::Mortal(period, phase) => readable(
                    indent,
                    "era",
                    &format!("Mortal, phase: {}, period: {}", phase, period),
                ),
            },
            ParsedData::Event(event) => event.show(indent, short_specs),
            ParsedData::GenesisHash(genesis_hash) => {
                readable(indent, "genesis_hash", &hex::encode(genesis_hash))
            }
            ParsedData::H160(h) => readable(indent, "H160", &hex::encode(h.0)),
            ParsedData::H256(h) => readable(indent, "H256", &hex::encode(h.0)),
            ParsedData::H512(h) => readable(indent, "H512", &hex::encode(h.0)),
            ParsedData::Id(id) => readable(
                indent,
                "Id",
                &id.to_ss58check_with_version(Ss58AddressFormat::custom(short_specs.base58prefix)),
            ),
            ParsedData::Option(option_data) => match option_data {
                Some(parsed_data) => parsed_data.show(indent, short_specs, display_balance),
                None => readable(indent, "option", "none"),
            },
            ParsedData::Sequence(sequence_data) => sequence_data.data.show(indent),
            ParsedData::SequenceRaw(sequence_raw_data) => {
                let mut out = String::new();
                for (i, x) in sequence_raw_data.data.iter().enumerate() {
                    if i > 0 {
                        out.push('\n')
                    }
                    out.push_str(&x.show(indent, short_specs, display_balance))
                }
                out
            }
            ParsedData::PerU16(a) => readable(indent, "per_u16", &a.deconstruct().to_string()),
            ParsedData::Percent(a) => readable(indent, "percent", &a.deconstruct().to_string()),
            ParsedData::Permill(a) => readable(indent, "permill", &a.deconstruct().to_string()),
            ParsedData::Perbill(a) => readable(indent, "perbill", &a.deconstruct().to_string()),
            ParsedData::Perquintill(a) => {
                readable(indent, "perquintill", &a.deconstruct().to_string())
            }
            ParsedData::PrimitiveBool(a) => readable(indent, "bool", &a.to_string()),
            ParsedData::PrimitiveChar(a) => readable(indent, "char", &a.to_string()),
            ParsedData::PrimitiveI8(a) => readable(indent, "i8", &a.to_string()),
            ParsedData::PrimitiveI16(a) => readable(indent, "i16", &a.to_string()),
            ParsedData::PrimitiveI32(a) => readable(indent, "i32", &a.to_string()),
            ParsedData::PrimitiveI64(a) => readable(indent, "i64", &a.to_string()),
            ParsedData::PrimitiveI128(a) => readable(indent, "i128", &a.to_string()),
            ParsedData::PrimitiveI256(a) => readable(indent, "i256", &a.to_string()),
            ParsedData::PrimitiveU8 { value, specialty } => display_with_specialty::<u8>(
                *value,
                indent,
                *specialty,
                short_specs,
                display_balance,
            ),
            ParsedData::PrimitiveU16 { value, specialty } => display_with_specialty::<u16>(
                *value,
                indent,
                *specialty,
                short_specs,
                display_balance,
            ),
            ParsedData::PrimitiveU32 { value, specialty } => display_with_specialty::<u32>(
                *value,
                indent,
                *specialty,
                short_specs,
                display_balance,
            ),
            ParsedData::PrimitiveU64 { value, specialty } => display_with_specialty::<u64>(
                *value,
                indent,
                *specialty,
                short_specs,
                display_balance,
            ),
            ParsedData::PrimitiveU128 { value, specialty } => display_with_specialty::<u128>(
                *value,
                indent,
                *specialty,
                short_specs,
                display_balance,
            ),
            ParsedData::PrimitiveU256(a) => readable(indent, "u256", &a.to_string()),
            ParsedData::PublicEd25519(public) => readable(
                indent,
                "Public Ed25519",
                &public
                    .to_ss58check_with_version(Ss58AddressFormat::custom(short_specs.base58prefix)),
            ),
            ParsedData::PublicSr25519(public) => readable(
                indent,
                "Public Sr25519",
                &public
                    .to_ss58check_with_version(Ss58AddressFormat::custom(short_specs.base58prefix)),
            ),
            ParsedData::PublicEcdsa(public) => readable(
                indent,
                "Public Ecdsa",
                &public
                    .to_ss58check_with_version(Ss58AddressFormat::custom(short_specs.base58prefix)),
            ),
            ParsedData::SignatureEd25519(signature) => {
                readable(indent, "Signature Ed25519", &hex::encode(signature.0))
            }
            ParsedData::SignatureSr25519(signature) => {
                readable(indent, "Signature Sr25519", &hex::encode(signature.0))
            }
            ParsedData::SignatureEcdsa(signature) => {
                readable(indent, "Signature Ecdsa", &hex::encode(signature.0))
            }
            ParsedData::Text(decoded_text) => readable(indent, "text", decoded_text),
            ParsedData::Tuple(extended_data_set) => {
                let mut out = String::new();
                for (i, extended_data) in extended_data_set.iter().enumerate() {
                    if i > 0 {
                        out.push('\n')
                    }
                    out.push_str(
                        &extended_data
                            .data
                            .show(indent, short_specs, display_balance),
                    )
                }
                out
            }
            ParsedData::Variant(variant_data) => {
                let mut out = readable(indent, "enum_variant_name", &variant_data.variant_name);
                if (variant_data.fields.len() == 1) && (variant_data.fields[0].field_name.is_none())
                {
                    out.push('\n');
                    out.push_str(&variant_data.fields[0].data.data.show(
                        indent + 1,
                        short_specs,
                        display_balance,
                    ))
                } else {
                    for (i, field_data) in variant_data.fields.iter().enumerate() {
                        out.push('\n');
                        match field_data.field_name {
                            Some(ref a) => out.push_str(&readable(indent + 1, "field_name", a)),
                            None => {
                                out.push_str(&readable(indent + 1, "field_number", &i.to_string()))
                            }
                        }
                        out.push('\n');
                        out.push_str(&field_data.data.data.show(
                            indent + 2,
                            short_specs,
                            display_balance,
                        ))
                    }
                }
                out
            }
        }
    }
}

fn readable(indent: u32, card_type: &str, card_payload: &str) -> String {
    format!(
        "{}{}: {}",
        "  ".repeat(indent as usize),
        card_type,
        card_payload
    )
}

fn display_with_specialty<T: StLenCheckSpecialtyCompact>(
    value: T,
    indent: u32,
    specialty: SpecialtyPrimitive,
    short_specs: &ShortSpecs,
    display_balance: bool,
) -> String {
    match specialty {
        SpecialtyPrimitive::None => readable(indent, T::default_card_name(), &value.to_string()),
        SpecialtyPrimitive::Balance => {
            if display_balance {
                let balance =
                    <T>::convert_balance_pretty(value, short_specs.decimals, &short_specs.unit);
                readable(
                    indent,
                    "balance",
                    &format!("{} {}", balance.number, balance.units),
                )
            } else {
                readable(indent, "balance_raw", &value.to_string())
            }
        }
        SpecialtyPrimitive::Tip => {
            let tip = <T>::convert_balance_pretty(value, short_specs.decimals, &short_specs.unit);
            readable(indent, "tip", &format!("{} {}", tip.number, tip.units))
        }
        SpecialtyPrimitive::Nonce => readable(indent, "nonce", &value.to_string()),
        SpecialtyPrimitive::SpecVersion => {
            readable(indent, "network", &format!("{}{}", short_specs.name, value))
        }
        SpecialtyPrimitive::TxVersion => readable(indent, "tx_version", &value.to_string()),
    }
}

#[derive(Clone, Debug)]
pub struct ExtendedCard {
    pub parser_card: ParserCard,
    pub indent: u32,
    pub info_flat: Vec<InfoFlat>,
}

#[derive(Clone, Debug)]
pub struct InfoFlat {
    pub docs: String,
    pub path_flat: String,
}

#[derive(Clone, Debug)]
pub enum ParserCard {
    Balance(Currency),
    BalanceRaw(String),
    BitVecU8Lsb0(BitVec<u8, Lsb0>),
    BitVecU16Lsb0(BitVec<u16, Lsb0>),
    BitVecU32Lsb0(BitVec<u32, Lsb0>),
    BitVecU64Lsb0(BitVec<u64, Lsb0>),
    BitVecU8Msb0(BitVec<u8, Msb0>),
    BitVecU16Msb0(BitVec<u16, Msb0>),
    BitVecU32Msb0(BitVec<u32, Msb0>),
    BitVecU64Msb0(BitVec<u64, Msb0>),
    BlockHash(H256),
    CallName(String),
    EnumVariantName(String),
    Era(Era),
    EventName(String),
    FieldName(String),
    FieldNumber(String),
    GenesisHash(H256),
    H160(H160),
    H256(H256),
    H512(H512),
    Id(AccountId32),
    NameSpecVersion { name: String, version: String },
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
    PublicEd25519(ed25519::Public),
    PublicSr25519(sr25519::Public),
    PublicEcdsa(ecdsa::Public),
    SequenceAnnounced,
    SequenceU8 { hex: String, text: Option<String> },
    SignatureEd25519(ed25519::Signature),
    SignatureSr25519(sr25519::Signature),
    SignatureEcdsa(ecdsa::Signature),
    Text(String),
    Tip(Currency),
    TxVersion(String),
}

impl ExtendedData {
    pub fn card(&self, indent: u32, display_balance: bool, short_specs: &ShortSpecs) -> Vec<ExtendedCard> {
        let info_flat = self.info.iter().map(|x| x.flatten()).collect();
        self.data.card(info_flat, indent, display_balance, short_specs)
    }
}

/*
pub fn card_extended_data(extended_data_set: &[ExtendedData]) -> Vec<ExtendedCard> {
    let mut out: Vec<ExtendedData> = Vec::new();
    let mut start_indent = 0;
    
    for extended_data in extended_data_set.iter() {
        match extended_data.data {
            
        }
    }
    
}

*/
