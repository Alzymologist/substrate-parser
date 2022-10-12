//! Decoders for special types: primitives, `PerThing` items, well-known arrays.
use num_bigint::{BigInt, BigUint};
use parity_scale_codec::{Decode, HasCompact};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};
use sp_core::{crypto::AccountId32, ByteArray, H160, H256, H512};
use sp_runtime::generic::Era;
use std::{convert::TryInto, mem::size_of};

use crate::cards::{ParsedData, Sequence, SequenceData};
use crate::compacts::get_compact;
use crate::error::ParserError;
use crate::printing_balance::AsBalance;
use crate::propagated::SpecialtySet;
use crate::special_indicators::{SpecialtyH256, SpecialtyPrimitive};

/// Stable length trait.
///
/// Encoded data length in bytes is always identical for the type.
pub(crate) trait StableLength: Sized {
    /// Encoded length for the type.
    fn len_encoded() -> usize;

    /// Type value from the data.
    ///
    /// Cut data is consumed.
    fn cut_and_decode(data: &mut Vec<u8>) -> Result<Self, ParserError>;
}

/// Implement [`StableLength`] for types with stable [`size_of`], value is
/// decoded.
macro_rules! impl_stable_length_mem_size_decode {
    ($($ty: ty), *) => {
        $(
            impl StableLength for $ty {
                fn len_encoded() -> usize {
                    size_of::<Self>()
                }
                fn cut_and_decode(data: &mut Vec<u8>) -> Result<Self, ParserError> {
                    match data.get(..Self::len_encoded()) {
                        Some(slice_to_decode) => {
                            let out = <Self>::decode(&mut &slice_to_decode[..])
                                .map_err(|_| ParserError::TypeFailure(stringify!($ty)))?;
                            *data = data[Self::len_encoded()..].to_vec();
                            Ok(out)
                        },
                        None => Err(ParserError::DataTooShort)
                    }
                }
            }
        )*
    }
}

impl_stable_length_mem_size_decode!(
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

/// Known size for [`BigInt`] and [`BigUint`].
const BIG_LEN: usize = 32;

/// Known size for [`char`].
const CHAR_LEN: usize = 4;

/// Implement [`StableLength`] for [`BigInt`] and [`BigUint`].
macro_rules! impl_stable_length_big_construct {
    ($($big: ty, $get: ident), *) => {
        $(
            impl StableLength for $big {
                fn len_encoded() -> usize {
                    BIG_LEN
                }
                fn cut_and_decode(data: &mut Vec<u8>) -> Result<Self, ParserError> {
                    match data.get(0..Self::len_encoded()) {
                        Some(slice_to_big256) => {
                            let out = Self::$get(slice_to_big256);
                            *data = data[Self::len_encoded()..].to_vec();
                            Ok(out)
                        },
                        None => Err(ParserError::DataTooShort),
                    }
                }
            }
        )*
    }
}

impl_stable_length_big_construct!(BigUint, from_bytes_le);
impl_stable_length_big_construct!(BigInt, from_signed_bytes_le);

impl StableLength for char {
    fn len_encoded() -> usize {
        CHAR_LEN
    }
    fn cut_and_decode(data: &mut Vec<u8>) -> Result<Self, ParserError> {
        match data.get(0..Self::len_encoded()) {
            Some(slice_to_char) => match char::from_u32(<u32>::from_le_bytes(
                slice_to_char
                    .try_into()
                    .expect("constant length, always fit"),
            )) {
                Some(ch) => {
                    *data = data[Self::len_encoded()..].to_vec();
                    Ok(ch)
                }
                None => Err(ParserError::TypeFailure("char")),
            },
            None => Err(ParserError::DataTooShort),
        }
    }
}

/// Implement [`StableLength`] for well-known arrays.
macro_rules! impl_stable_length_array {
    ($($array: ty, $length: stmt, $make: ident), *) => {
        $(
            impl StableLength for $array {
                fn len_encoded() -> usize {
                    $length
                }
                fn cut_and_decode(data: &mut Vec<u8>) -> Result<Self, ParserError> {
                    match data.get(0..Self::len_encoded()) {
                        Some(slice_to_array) => {
                            let out = Self::$make(slice_to_array.try_into().expect("stable known length"));
                            *data = data[Self::len_encoded()..].to_vec();
                            Ok(out)
                        },
                        None => Err(ParserError::DataTooShort),
                    }
                }
            }
        )*
    }
}

impl_stable_length_array!(AccountId32, Self::LEN, new);
impl_stable_length_array!(sp_core::ed25519::Public, Self::LEN, from_raw);
impl_stable_length_array!(sp_core::sr25519::Public, Self::LEN, from_raw);
impl_stable_length_array!(sp_core::ecdsa::Public, Self::LEN, from_raw);

/// Known size for [sp_core::ed25519::Signature] and
/// [sp_core::sr25519::Signature].
const SIGNATURE_LEN_64: usize = 64;

/// Known size for [sp_core::ecdsa::Signature].
const SIGNATURE_LEN_65: usize = 65;

impl_stable_length_array!(sp_core::ed25519::Signature, SIGNATURE_LEN_64, from_raw);
impl_stable_length_array!(sp_core::sr25519::Signature, SIGNATURE_LEN_64, from_raw);
impl_stable_length_array!(sp_core::ecdsa::Signature, SIGNATURE_LEN_65, from_raw);

/// Implement [`StableLength`] for well-known hashes.
macro_rules! impl_stable_length_hash {
    ($($array: ty), *) => {
        $(
            impl StableLength for $array {
                fn len_encoded() -> usize {
                    Self::len_bytes()
                }
                fn cut_and_decode(data: &mut Vec<u8>) -> Result<Self, ParserError> {
                    match data.get(0..Self::len_encoded()) {
                        Some(slice_to_array) => {
                            let out = Self(slice_to_array.try_into().expect("stable known length"));
                            *data = data[Self::len_encoded()..].to_vec();
                            Ok(out)
                        },
                        None => Err(ParserError::DataTooShort),
                    }
                }
            }
        )*
    }
}

impl_stable_length_hash!(H160, H256, H512);

/// Unsigned integer trait. Compatible with compacts, uses the propagated
/// [`SpecialtyPrimitive`].
pub(crate) trait UnsignedInteger:
    StableLength + AsBalance + HasCompact + std::fmt::Display
{
    fn parse_unsigned_integer(
        data: &mut Vec<u8>,
        specialty_set: SpecialtySet,
    ) -> Result<ParsedData, ParserError>;
    fn default_card_name() -> &'static str;
}

/// Implement [`UnsignedInteger`] trait for all unsigned integers.
macro_rules! impl_unsigned_integer {
    ($($ty: ty, $enum_variant: ident), *) => {
        $(
            impl UnsignedInteger for $ty {
                fn parse_unsigned_integer(data: &mut Vec<u8>, specialty_set: SpecialtySet) -> Result<ParsedData, ParserError> {
                    let value = {
                        if specialty_set.is_compact {get_compact::<Self>(data)?}
                        else {<Self>::cut_and_decode(data)?}
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

impl_unsigned_integer!(u8, PrimitiveU8);
impl_unsigned_integer!(u16, PrimitiveU16);
impl_unsigned_integer!(u32, PrimitiveU32);
impl_unsigned_integer!(u64, PrimitiveU64);
impl_unsigned_integer!(u128, PrimitiveU128);

/// Trait for stable length types that must be checked for propagated compact
/// flag.
pub(crate) trait CheckCompact: StableLength {
    fn parse_check_compact(data: &mut Vec<u8>, is_compact: bool)
        -> Result<ParsedData, ParserError>;
}

/// Implement [`CheckCompact`] for `PerThing` that can be compact.
macro_rules! impl_allow_compact {
    ($($perthing: ident), *) => {
        $(
            impl CheckCompact for $perthing where $perthing: HasCompact {
                fn parse_check_compact(data: &mut Vec<u8>, is_compact: bool) -> Result<ParsedData, ParserError> {
                    let value = {
                        if is_compact {get_compact::<Self>(data)?}
                        else {<Self>::cut_and_decode(data)?}
                    };
                    Ok(ParsedData::$perthing(value))
                }
            }
        )*
    }
}

impl_allow_compact!(PerU16, Percent, Permill, Perbill, Perquintill);

/// Implement [`CheckCompact`] for types that can not be compact.
macro_rules! impl_block_compact {
    ($($ty: ty, $enum_variant: ident), *) => {
        $(
            impl CheckCompact for $ty {
                fn parse_check_compact(data: &mut Vec<u8>, is_compact: bool) -> Result<ParsedData, ParserError> {
                    let value = {
                        if is_compact {return Err(ParserError::UnexpectedCompactInsides)}
                        else {<Self>::cut_and_decode(data)?}
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
impl_block_compact!(AccountId32, Id);
impl_block_compact!(sp_core::ed25519::Public, PublicEd25519);
impl_block_compact!(sp_core::sr25519::Public, PublicSr25519);
impl_block_compact!(sp_core::ecdsa::Public, PublicEcdsa);
impl_block_compact!(sp_core::ed25519::Signature, SignatureEd25519);
impl_block_compact!(sp_core::sr25519::Signature, SignatureSr25519);
impl_block_compact!(sp_core::ecdsa::Signature, SignatureEcdsa);
impl_block_compact!(H160, H160);
impl_block_compact!(H512, H512);

/// Trait to collect some variants of [`ParsedData`] into [`Sequence`].
///
/// Some simple types are easier displayed if `Vec<ParsedData>` is re-arranged
/// into single `ParsedData::Sequence(_)`. This is expecially true for `u8` and
/// `Vec<u8>`.
trait Collectable: Sized {
    fn husk_set(parsed_data_set: &[ParsedData]) -> Option<Sequence>;
}

/// Implement [`Collectable`] for unsigned integers.
macro_rules! impl_collect_vec {
    ($($ty: ty, $enum_variant_input: ident, $enum_variant_output: ident), *) => {
        $(
            impl Collectable for $ty {
                /// Collecting data into `Sequence`.
                ///
                /// This function is unfallible. If somehow not all data is
                /// of the same `ParsedData` variant, the `Sequence` just does
                /// not get assembled and parsed data would be displayed as
                /// `SequenceRaw`.
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
                                if b != &sequence_data.element_info {
                                    return None;
                                }
                            }
                            None => {
                                inner_element_info = Some(sequence_data.element_info.to_owned());
                            }
                        }
                        out.push(a.clone())
                    } else {
                        return None;
                    }
                }
                ParsedData::SequenceRaw(a) => {
                    if a.data.is_empty() {
                        out.push(Vec::new())
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        let inner_element_info = match inner_element_info {
            Some(a) => a,
            None => Vec::new(),
        };
        Some(Sequence::VecU8 {
            sequence: out,
            inner_element_info,
        })
    }
}

/// Try collecting [`Sequence`]. Expected variant of [`ParsedData`] is
/// determined by the first set element.
pub(crate) fn wrap_sequence(set: &[ParsedData]) -> Option<Sequence> {
    match set.first() {
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

/// Parse part of the data as [`H256`], apply available [`SpecialtyH256`].
///
/// Used data gets cut off in the process.
pub(crate) fn special_case_h256(
    data: &mut Vec<u8>,
    specialty_hash: SpecialtyH256,
) -> Result<ParsedData, ParserError> {
    let hash = H256::cut_and_decode(data)?;
    match specialty_hash {
        SpecialtyH256::GenesisHash => Ok(ParsedData::GenesisHash(hash)),
        SpecialtyH256::BlockHash => Ok(ParsedData::BlockHash(hash)),
        SpecialtyH256::None => Ok(ParsedData::H256(hash)),
    }
}

/// Parse part of the data as [`Era`].
///
/// Used data gets cut off in the process.
pub(crate) fn special_case_era(data: &mut Vec<u8>) -> Result<ParsedData, ParserError> {
    let (era_data, remaining_vector) = match data.first() {
        Some(0) => (data[0..1].to_vec(), data[1..].to_vec()),
        Some(_) => match data.get(0..2) {
            Some(a) => (a.to_vec(), data[2..].to_vec()),
            None => return Err(ParserError::DataTooShort),
        },
        None => return Err(ParserError::DataTooShort),
    };
    *data = remaining_vector;
    match Era::decode(&mut &era_data[..]) {
        Ok(a) => Ok(ParsedData::Era(a)),
        Err(_) => Err(ParserError::TypeFailure("Era")),
    }
}
