//! Decoder elements common for all metadata versions
//!
use num_bigint::{BigInt, BigUint};
use parity_scale_codec::{Decode, HasCompact};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};
use sp_core::{crypto::AccountId32, H160, H256, H512};
use sp_runtime::generic::Era;
use std::{convert::TryInto, mem::size_of};

use crate::cards::{ParsedData, Sequence, SequenceData};
use crate::compacts::get_compact;
use crate::error::{ParserDecodingError, ParserError};
use crate::printing_balance::AsBalance;
use crate::special_indicators::{SpecialtyH256, SpecialtyPrimitive, SpecialtySet};

pub(crate) trait StLen: Sized {
    fn decode_value(data: &mut Vec<u8>) -> Result<Self, ParserError>;
}

macro_rules! impl_stable_length_decodable {
    ($($ty: ty), *) => {
        $(
            impl StLen for $ty {
                fn decode_value(data: &mut Vec<u8>) -> Result<Self, ParserError> {
                    let length = size_of::<Self>();
                    match data.get(..length) {
                        Some(slice_to_decode) => {
                            let out = <Self>::decode(&mut &slice_to_decode[..])
                                .map_err(|_| ParserError::Decoding(ParserDecodingError::PrimitiveFailure(stringify!($ty))))?;
                            *data = data[length..].to_vec();
                            Ok(out)
                        },
                        None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort))
                    }
                }
            }
        )*
    }
}

impl_stable_length_decodable!(
    bool,
    i8,
    i16,
    i32,
    i64,
    i128,
    u8,
    u16,
    u32,
    u64,
    u128,
    PerU16,
    Percent,
    Permill,
    Perbill,
    Perquintill
);

macro_rules! impl_stable_length_big {
    ($($big: ty, $get: ident), *) => {
        $(
            impl StLen for $big {
                fn decode_value(data: &mut Vec<u8>) -> Result<Self, ParserError> {
                    match data.get(0..32) {
                        Some(slice_to_big256) => {
                            let out = Self::$get(slice_to_big256);
                            *data = data[32..].to_vec();
                            Ok(out)
                        },
                        None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort)),
                    }
                }
            }
        )*
    }
}

impl_stable_length_big!(BigUint, from_bytes_le);
impl_stable_length_big!(BigInt, from_signed_bytes_le);

impl StLen for char {
    fn decode_value(data: &mut Vec<u8>) -> Result<Self, ParserError> {
        match data.get(0..4) {
            Some(slice_to_char) => match char::from_u32(<u32>::from_le_bytes(
                slice_to_char
                    .try_into()
                    .expect("contstant length, always fit"),
            )) {
                Some(ch) => {
                    *data = data[4..].to_vec();
                    Ok(ch)
                }
                None => Err(ParserError::Decoding(
                    ParserDecodingError::PrimitiveFailure("char"),
                )),
            },
            None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort)),
        }
    }
}

pub(crate) trait StLenCheckSpecialtyCompact:
    StLen + AsBalance + HasCompact + std::fmt::Display
{
    fn decode_checked(
        data: &mut Vec<u8>,
        specialty_set: SpecialtySet,
    ) -> Result<ParsedData, ParserError>;
    fn default_card_name() -> &'static str;
}

macro_rules! impl_check_specialty_compact {
    ($($ty: ty, $enum_variant: ident), *) => {
        $(
            impl StLenCheckSpecialtyCompact for $ty {
                fn decode_checked(data: &mut Vec<u8>, specialty_set: SpecialtySet) -> Result<ParsedData, ParserError> {
                    let value = {
                        if specialty_set.is_compact {get_compact::<Self>(data)?}
                        else {<Self>::decode_value(data)?}
                    };
                    Ok(ParsedData::$enum_variant{value, specialty: specialty_set.primitive()})
                }
                fn default_card_name() -> &'static str {
                    stringify!($ty)
                }
            }
        )*
    }
}

impl_check_specialty_compact!(u8, PrimitiveU8);
impl_check_specialty_compact!(u16, PrimitiveU16);
impl_check_specialty_compact!(u32, PrimitiveU32);
impl_check_specialty_compact!(u64, PrimitiveU64);
impl_check_specialty_compact!(u128, PrimitiveU128);

pub(crate) trait StLenCheckCompact: StLen {
    fn decode_checked(data: &mut Vec<u8>, is_compact: bool) -> Result<ParsedData, ParserError>;
}

macro_rules! impl_allow_compact {
    ($($perthing: ident), *) => {
        $(
            impl StLenCheckCompact for $perthing where $perthing: HasCompact {
                fn decode_checked(data: &mut Vec<u8>, is_compact: bool) -> Result<ParsedData, ParserError> {
                    let value = {
                        if is_compact {get_compact::<Self>(data)?}
                        else {<Self>::decode_value(data)?}
                    };
                    Ok(ParsedData::$perthing(value))
                }
            }
        )*
    }
}

impl_allow_compact!(PerU16, Percent, Permill, Perbill, Perquintill);

macro_rules! impl_block_compact {
    ($($ty: ty, $enum_variant: ident), *) => {
        $(
            impl StLenCheckCompact for $ty {
                fn decode_checked(data: &mut Vec<u8>, is_compact: bool) -> Result<ParsedData, ParserError> {
                    let value = {
                        if is_compact {return Err(ParserError::Decoding(
                            ParserDecodingError::UnexpectedCompactInsides,
                        ))}
                        else {<Self>::decode_value(data)?}
                    };
                    Ok(ParsedData::$enum_variant(value))
                }
            }
        )*
    }
}

impl_block_compact!(bool, PrimitiveBool);
impl_block_compact!(char, PrimitiveChar);
impl_block_compact!(i8, PrimitiveI8);
impl_block_compact!(i16, PrimitiveI16);
impl_block_compact!(i32, PrimitiveI32);
impl_block_compact!(i64, PrimitiveI64);
impl_block_compact!(i128, PrimitiveI128);
impl_block_compact!(BigInt, PrimitiveI256);
impl_block_compact!(BigUint, PrimitiveU256);

pub trait Collectable: Sized {
    fn husk_set(parsed_data_set: &[ParsedData]) -> Option<Sequence>;
}

macro_rules! impl_collect_vec {
    ($($ty: ty, $enum_variant_input: ident, $enum_variant_output: ident), *) => {
        $(
            impl Collectable for $ty {
                fn husk_set(parsed_data_set: &[ParsedData]) -> Option<Sequence> {
                    let mut out: Vec<Self> = Vec::new();
                    for x in parsed_data_set.iter() {
                        if let ParsedData::$enum_variant_input{value: a, specialty: SpecialtyPrimitive::None} = x {out.push(*a)}
                        else {return None}
                    }
                    Some(Sequence::$enum_variant_output(out))
                }
            }
        )*
    }
}

impl_collect_vec!(u8, PrimitiveU8, U8);
impl_collect_vec!(u16, PrimitiveU16, U16);
impl_collect_vec!(u32, PrimitiveU32, U32);
impl_collect_vec!(u64, PrimitiveU64, U64);
impl_collect_vec!(u128, PrimitiveU128, U128);

impl Collectable for Vec<u8> {
    fn husk_set(parsed_data_set: &[ParsedData]) -> Option<Sequence> {
        let mut out: Vec<Self> = Vec::new();
        let mut inner_element_info = None;

        for x in parsed_data_set.iter() {
            match x {
                ParsedData::Sequence(sequence_data) => {
                    if let Sequence::U8(a) = &sequence_data.data {
                        match inner_element_info {
                            Some(ref b) => {
                                if b != &sequence_data.element_info {return None}
                            },
                            None => {
                                inner_element_info = Some(sequence_data.element_info.to_owned());
                            },
                        }
                        out.push(a.clone())
                    }
                    else {return None}
                },
                ParsedData::SequenceRaw(a) => {
                    if a.data.is_empty() {out.push(Vec::new())}
                    else {return None}
                },
                _ => return None,
            }
        }
        let inner_element_info = match inner_element_info {
            Some(a) => a,
            None => Vec::new(),
        };
        Some(Sequence::VecU8{sequence: out, inner_element_info})
    }
}

pub fn wrap_sequence(set: &[ParsedData]) -> Option<Sequence> {
    match set.get(0) {
        Some(ParsedData::PrimitiveU8 { .. }) => u8::husk_set(set),
        Some(ParsedData::PrimitiveU16 { .. }) => u16::husk_set(set),
        Some(ParsedData::PrimitiveU32 { .. }) => u32::husk_set(set),
        Some(ParsedData::PrimitiveU64 { .. }) => u64::husk_set(set),
        Some(ParsedData::PrimitiveU128 { .. }) => u128::husk_set(set),
        Some(ParsedData::Sequence(SequenceData {
            element_info: _,
            data: Sequence::U8(_),
        })) => <Vec<u8>>::husk_set(set),
        _ => None,
    }
}

/// Function to decode of AccountId special case and transform the result into base58 format.
///
/// The function decodes only a single AccountId type entry,
/// removes already decoded part of input data Vec<u8>,
/// and returns whatever remains as DecodedOut field remaining_vector, which is processed later separately.
///
/// The function takes as arguments
/// - data (remaining Vec<u8> of data),
///
/// The function outputs the DecodedOut value in case of success.
///
/// Resulting AccountId in base58 form is added to fancy_out on js card "Id".
pub(crate) fn special_case_account_id32(data: &mut Vec<u8>) -> Result<ParsedData, ParserError> {
    match data.get(0..32) {
        Some(a) => {
            let array_decoded: [u8; 32] = a.try_into().expect("constant length, always fits");
            *data = data[32..].to_vec();
            let account_id = AccountId32::new(array_decoded);
            Ok(ParsedData::Id(account_id))
        }
        None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort)),
    }
}

macro_rules! crypto_type_decoder {
    ($func:ident, $module:ident, $target:ident, $len:literal, $enum_variant: ident) => {
        pub(crate) fn $func(data: &mut Vec<u8>) -> Result<ParsedData, ParserError> {
            match data.get(0..$len) {
                Some(a) => {
                    let array_decoded: [u8; $len] =
                        a.try_into().expect("constant length, always fits");
                    *data = data[$len..].to_vec();
                    let public = sp_core::$module::$target::from_raw(array_decoded);
                    Ok(ParsedData::$enum_variant(public))
                }
                None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort)),
            }
        }
    };
}

crypto_type_decoder!(
    special_case_ed25519_public,
    ed25519,
    Public,
    32,
    PublicEd25519
);
crypto_type_decoder!(
    special_case_sr25519_public,
    sr25519,
    Public,
    32,
    PublicSr25519
);
crypto_type_decoder!(special_case_ecdsa_public, ecdsa, Public, 33, PublicEcdsa);
crypto_type_decoder!(
    special_case_ed25519_signature,
    ed25519,
    Signature,
    64,
    SignatureEd25519
);
crypto_type_decoder!(
    special_case_sr25519_signature,
    sr25519,
    Signature,
    64,
    SignatureSr25519
);
crypto_type_decoder!(
    special_case_ecdsa_signature,
    ecdsa,
    Signature,
    65,
    SignatureEcdsa
);

pub(crate) trait SpecialArray {
    fn cut_and_decode(data: &mut Vec<u8>) -> Result<ParsedData, ParserError>;
}

macro_rules! impl_special_array_h {
    ($($hash: ident), *) => {
        $(
            impl SpecialArray for $hash {
                fn cut_and_decode(data: &mut Vec<u8>) -> Result<ParsedData, ParserError> {
                    let length = <$hash>::len_bytes();
                    match data.get(..length) {
                        Some(slice) => {
                            let out_data = $hash(slice.try_into().expect("fixed checked length, always fits"));
                            *data = data[length..].to_vec();
                            Ok(ParsedData::$hash(out_data))
                        },
                        None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort))
                    }
                }
            }
        )*
    }
}

impl_special_array_h!(H160, H512);

pub fn special_case_h256(
    data: &mut Vec<u8>,
    specialty_hash: SpecialtyH256,
) -> Result<ParsedData, ParserError> {
    let length = H256::len_bytes();
    match data.get(..length) {
        Some(slice) => {
            let out_data = H256(slice.try_into().expect("fixed checked length, always fits"));
            *data = data[length..].to_vec();
            match specialty_hash {
                SpecialtyH256::GenesisHash => Ok(ParsedData::GenesisHash(out_data)),
                SpecialtyH256::BlockHash => Ok(ParsedData::BlockHash(out_data)),
                SpecialtyH256::None => Ok(ParsedData::H256(out_data)),
            }
        }
        None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort)),
    }
}

pub fn special_case_era(data: &mut Vec<u8>) -> Result<ParsedData, ParserError> {
    let (era_data, remaining_vector) = match data.get(0) {
        Some(0) => (data[0..1].to_vec(), data[1..].to_vec()),
        Some(_) => match data.get(0..2) {
            Some(a) => (a.to_vec(), data[2..].to_vec()),
            None => return Err(ParserError::Decoding(ParserDecodingError::DataTooShort)),
        },
        None => return Err(ParserError::Decoding(ParserDecodingError::DataTooShort)),
    };
    *data = remaining_vector;
    match Era::decode(&mut &era_data[..]) {
        Ok(a) => Ok(ParsedData::Era(a)),
        Err(_) => Err(ParserError::Decoding(ParserDecodingError::Era)),
    }
}
