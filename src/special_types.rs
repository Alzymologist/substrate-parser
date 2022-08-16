//! Decoder elements common for all metadata versions
//!
use num_bigint::{BigInt, BigUint};
use parity_scale_codec::{Decode, HasCompact};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};
use sp_core::{crypto::AccountId32, H160, H256, H512};
use sp_runtime::generic::Era;
use std::{convert::TryInto, mem::size_of};

use crate::cards::ParsedData;
use crate::compacts::get_compact;
use crate::error::{ParserDecodingError, ParserError};
use crate::printing_balance::AsBalance;
use crate::special_indicators::{SpecialtyH256, SpecialtySet};

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
    fn decode_checked(
        data: &mut Vec<u8>,
        is_compact: bool,
    ) -> Result<ParsedData, ParserError>;
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

pub(crate) trait SpecialArray: {
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

pub fn special_case_h256(data: &mut Vec<u8>, specialty_hash: SpecialtyH256) -> Result<ParsedData, ParserError> {
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
        },
        None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort))
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
