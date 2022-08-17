//! Parsed cards to display decoded call and extensions data
use bitvec::prelude::{BitVec, Lsb0, Msb0};
use num_bigint::{BigInt, BigUint};
use scale_info::{Path, form::PortableForm};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};
use sp_core::{
    crypto::{AccountId32, Ss58AddressFormat, Ss58Codec},
    H160, H256, H512,
};
use sp_runtime::generic::Era;

use crate::ShortSpecs;
use crate::special_indicators::SpecialtyPrimitive;
use crate::special_types::StLenCheckSpecialtyCompact;

#[derive(Clone, Debug)]
pub struct Info {
    pub docs: String,
    pub path: Path<PortableForm>,
}

impl Info {
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()&&self.path.is_empty()
    }
}

/// Each decoding results in `ExtendedData`
#[derive(Clone, Debug)]
pub struct ExtendedData {
    pub info: Vec<Info>,
    pub data: ParsedData,
}

#[derive(Clone, Debug)]
pub struct Call {
    pub info_pallet: Info,
    pub docs_call: String,
    pub pallet: String,
    pub call: String,
    pub fields: Vec<FieldData>,
}

impl Call {
    pub fn is_balance_display(&self) -> bool {
        self.pallet == "Balances" || self.pallet == "Staking"
    }
    pub fn show(&self, indent: u32, short_specs: &ShortSpecs) -> String {
        let mut out = [
            readable(indent, "pallet", &self.pallet),
            String::from("\n"),
            readable(indent+1, "call", &self.call),
        ].concat();
        for (i, field_data) in self.fields.iter().enumerate() {
            out.push('\n');
            match field_data.field_name {
                Some(ref a) => out.push_str(&readable(indent+2, "field_name", a)),
                None => out.push_str(&readable(indent+2, "field_number", &i.to_string()))
            }
            out.push('\n');
            out.push_str(&field_data.data.data.show(indent+3, short_specs, self.is_balance_display()))
        }
        out
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
    VecU8(Vec<Vec<u8>>),
}

impl Sequence {
    fn show(&self, indent: u32) -> String {
        match &self {
            Sequence::U8(a) => readable(indent, "sequence u8", &hex::encode(a)),
            Sequence::U16(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i>0 {out.push('\n')}
                    out.push_str(&readable(indent, "u16", &x.to_string()));
                }
                out
            }
            Sequence::U32(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i>0 {out.push('\n')}
                    out.push_str(&readable(indent, "u32", &x.to_string()));
                }
                out
            },
            Sequence::U64(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i>0 {out.push('\n')}
                    out.push_str(&readable(indent, "u64", &x.to_string()));
                }
                out
            },
            Sequence::U128(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i>0 {out.push('\n')}
                    out.push_str(&readable(indent, "u128", &x.to_string()));
                }
                out
            },
            Sequence::VecU8(a) => {
                let mut out = String::new();
                for (i, x) in a.iter().enumerate() {
                    if i>0 {out.push('\n')}
                    out.push_str(&readable(indent, "sequence u8", &hex::encode(x)));
                }
                out
            },
        }
    }
}

#[derive(Clone, Debug)]
pub enum ParsedData {
    Call(Call),
    Composite(Vec<FieldData>), // structs
    Tuple(Vec<ExtendedData>), // tuples
    Variant(VariantData),
    Option(Option<Box<ParsedData>>),
    Sequence(SequenceData),
    SequenceRaw(SequenceRawData),
    PrimitiveBool(bool),
    PrimitiveChar(char),
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
    PrimitiveI8(i8),
    PrimitiveI16(i16),
    PrimitiveI32(i32),
    PrimitiveI64(i64),
    PrimitiveI128(i128),
    PrimitiveI256(BigInt),
    PerU16(PerU16),
    Percent(Percent),
    Permill(Permill),
    Perbill(Perbill),
    Perquintill(Perquintill),
    Text(String),
    Id(AccountId32),
    H160(H160),
    H256(H256),
    H512(H512),
    None,
    IdentityField(String),
    BitVec(String), // String from printing BitVec
    BitVecU8Lsb0(BitVec<u8, Lsb0>),
    BitVecU16Lsb0(BitVec<u16, Lsb0>),
    BitVecU32Lsb0(BitVec<u32, Lsb0>),
    BitVecU64Lsb0(BitVec<u64, Lsb0>),
    BitVecU8Msb0(BitVec<u8, Msb0>),
    BitVecU16Msb0(BitVec<u16, Msb0>),
    BitVecU32Msb0(BitVec<u32, Msb0>),
    BitVecU64Msb0(BitVec<u64, Msb0>),
    Era(Era),
    BlockHash(H256),
    GenesisHash(H256),
}

impl ParsedData {
    pub fn show(&self, indent: u32, short_specs: &ShortSpecs, display_balance: bool) -> String {
        match &self {
            ParsedData::Call(call) => call.show(indent, short_specs),
            ParsedData::Composite(field_data_set) => {
                if (field_data_set.len() == 1)&&(field_data_set[0].field_name.is_none()) {
                    field_data_set[0].data.data.show(indent, short_specs, display_balance)
                }
                else {
                    let mut out = String::new();
                    for (i, field_data) in field_data_set.iter().enumerate() {
                        if i>0 {out.push('\n')}
                        match field_data.field_name {
                            Some(ref a) => out.push_str(&readable(indent, "field_name", a)),
                            None => out.push_str(&readable(indent, "field_number", &i.to_string()))
                        }
                        out.push('\n');
                        out.push_str(&field_data.data.data.show(indent+1, short_specs, display_balance))
                    }
                    out
                }
            },
            ParsedData::Tuple(extended_data_set) => {
                let mut out = String::new();
                for (i, extended_data) in extended_data_set.iter().enumerate() {
                    if i>0 {out.push('\n')}
                    out.push_str(&extended_data.data.show(indent, short_specs, display_balance))
                }
                out
            },
            ParsedData::Variant(variant_data) => {
                let mut out = readable(indent, "enum_variant_name", &variant_data.variant_name);
                if (variant_data.fields.len() == 1)&&(variant_data.fields[0].field_name.is_none()) {
                    out.push('\n');
                    out.push_str(&variant_data.fields[0].data.data.show(indent+1, short_specs, display_balance))
                }
                else {
                    for (i, field_data) in variant_data.fields.iter().enumerate() {
                        out.push('\n');
                        match field_data.field_name {
                            Some(ref a) => out.push_str(&readable(indent+1, "field_name", a)),
                            None => out.push_str(&readable(indent+1, "field_number", &i.to_string()))
                        }
                        out.push('\n');
                        out.push_str(&field_data.data.data.show(indent+2, short_specs, display_balance))
                    }
                }
                out
            },
            ParsedData::Option(option_data) => {
                match option_data {
                    Some(parsed_data) => parsed_data.show(indent, short_specs, display_balance),
                    None => readable(indent, "none", ""),
                }
            },
            ParsedData::Sequence(sequence_data) => {
                sequence_data.data.show(indent)
            },
            ParsedData::SequenceRaw(sequence_raw_data) => {
                let mut out = String::new();
                for (i, x) in sequence_raw_data.data.iter().enumerate() {
                    if i>0 {out.push('\n')}
                    out.push_str(&x.show(indent, short_specs, display_balance))
                }
                out
            },
            ParsedData::PrimitiveBool(a) => readable(indent, "bool", &a.to_string()),
            ParsedData::PrimitiveChar(a) => readable(indent, "char", &a.to_string()),
            ParsedData::PrimitiveU8 { value, specialty } => {
                display_with_specialty::<u8>(*value, indent, *specialty, short_specs, display_balance)
            }
            ParsedData::PrimitiveU16 { value, specialty } => {
                display_with_specialty::<u16>(*value, indent, *specialty, short_specs, display_balance)
            }
            ParsedData::PrimitiveU32 { value, specialty } => {
                display_with_specialty::<u32>(*value, indent, *specialty, short_specs, display_balance)
            }
            ParsedData::PrimitiveU64 { value, specialty } => {
                display_with_specialty::<u64>(*value, indent, *specialty, short_specs, display_balance)
            }
            ParsedData::PrimitiveU128 { value, specialty } => {
                display_with_specialty::<u128>(*value, indent, *specialty, short_specs, display_balance)
            }
            ParsedData::PrimitiveU256(a) => readable(indent, "u256", &a.to_string()),
            ParsedData::PrimitiveI8(a) => readable(indent, "i8", &a.to_string()),
            ParsedData::PrimitiveI16(a) => readable(indent, "i16", &a.to_string()),
            ParsedData::PrimitiveI32(a) => readable(indent, "i32", &a.to_string()),
            ParsedData::PrimitiveI64(a) => readable(indent, "i64", &a.to_string()),
            ParsedData::PrimitiveI128(a) => readable(indent, "i128", &a.to_string()),
            ParsedData::PrimitiveI256(a) => readable(indent, "i256", &a.to_string()),
            ParsedData::PerU16(a) => readable(indent, "per_u16", &a.deconstruct().to_string()),
            ParsedData::Percent(a) => readable(indent, "percent", &a.deconstruct().to_string()),
            ParsedData::Permill(a) => readable(indent, "permill", &a.deconstruct().to_string()),
            ParsedData::Perbill(a) => readable(indent, "perbill", &a.deconstruct().to_string()),
            ParsedData::Perquintill(a) => {
                readable(indent, "perquintill", &a.deconstruct().to_string())
            }
            ParsedData::Text(decoded_text) => readable(indent, "text", decoded_text),
            ParsedData::Id(id) => readable(
                indent,
                "Id",
                &id.to_ss58check_with_version(Ss58AddressFormat::custom(short_specs.base58prefix)),
            ),
            ParsedData::H160(h) => readable(indent, "H160", &hex::encode(h.0)),
            ParsedData::H256(h) => readable(indent, "H256", &hex::encode(h.0)),
            ParsedData::H512(h) => readable(indent, "H512", &hex::encode(h.0)),
            ParsedData::None => readable(indent, "none", ""),
            ParsedData::IdentityField(variant) => readable(indent, "identity_field", variant),
            ParsedData::BitVec(bv) => readable(indent, "bitvec", bv),
            ParsedData::BitVecU8Lsb0(a) => readable(indent, "BitVec<u8, Lsb0>", &a.to_string()),
            ParsedData::BitVecU16Lsb0(a) => readable(indent, "BitVec<u16, Lsb0>", &a.to_string()),
            ParsedData::BitVecU32Lsb0(a) => readable(indent, "BitVec<u32, Lsb0>", &a.to_string()),
            ParsedData::BitVecU64Lsb0(a) => readable(indent, "BitVec<u64, Lsb0>", &a.to_string()),
            ParsedData::BitVecU8Msb0(a) => readable(indent, "BitVec<u8, Msb0>", &a.to_string()),
            ParsedData::BitVecU16Msb0(a) => readable(indent, "BitVec<u16, Msb0>", &a.to_string()),
            ParsedData::BitVecU32Msb0(a) => readable(indent, "BitVec<u32, Msb0>", &a.to_string()),
            ParsedData::BitVecU64Msb0(a) => readable(indent, "BitVec<u64, Msb0>", &a.to_string()),
            ParsedData::Era(era) => match era {
                Era::Immortal => readable(indent, "era", "Immortal"),
                Era::Mortal(period, phase) => readable(
                    indent,
                    "era",
                    &format!("Mortal, phase: {}, period: {}", phase, period),
                ),
            },
            ParsedData::BlockHash(block_hash) => {
                readable(indent, "block_hash", &hex::encode(block_hash))
            }
            ParsedData::GenesisHash(genesis_hash) => {
                readable(indent, "genesis_hash", &hex::encode(genesis_hash))
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
            }
            else {
                readable(
                    indent,
                    "balance_raw",
                    &value.to_string(),
                )
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
