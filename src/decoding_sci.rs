//! Decode data using [`RuntimeMetadataV14`].
use bitvec::prelude::{BitVec, Lsb0, Msb0};
use frame_metadata::v14::RuntimeMetadataV14;
use num_bigint::{BigInt, BigUint};
use parity_scale_codec::{Decode, OptionBool};
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, Field, Type, TypeDef, TypeDefBitSequence,
    TypeDefPrimitive, Variant,
};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};
use sp_core::{H160, H512};

use crate::cards::{
    Call, Documented, Event, ExtendedData, FieldData, Info, PalletSpecificData, ParsedData,
    SequenceData, SequenceRawData, VariantData,
};
use crate::compacts::{cut_compact, get_compact};
use crate::error::{ParserError, SignableError};
use crate::special_indicators::{
    Checker, Hint, PalletSpecificItem, Propagated, SpecialtySet, SpecialtyTypeChecked,
    SpecialtyTypeHinted,
};
use crate::special_types::{
    special_case_account_id32, special_case_ecdsa_public, special_case_ecdsa_signature,
    special_case_ed25519_public, special_case_ed25519_signature, special_case_era,
    special_case_h256, special_case_sr25519_public, special_case_sr25519_signature, wrap_sequence,
    SpecialArray, StLenCheckCompact, StLenCheckSpecialtyCompact,
};

/// Function to decode types that are variants of TypeDefPrimitive enum.
///
/// The function decodes only given type found_ty, removes already decoded part of input data Vec<u8>,
/// and returns whatever remains as DecodedOut field remaining_vector, which is processed later separately.
///
/// The function takes as arguments
/// - found_ty (TypeDefPrimitive, found in the previous iteration)
/// - data (remaining Vec<u8> of data),
///
/// The function outputs the DecodedOut value in case of success.
fn decode_type_def_primitive(
    found_ty: &TypeDefPrimitive,
    data: &mut Vec<u8>,
    specialty_set: SpecialtySet,
) -> Result<ParsedData, ParserError> {
    match found_ty {
        TypeDefPrimitive::Bool => bool::decode_checked(data, specialty_set.is_compact),
        TypeDefPrimitive::Char => char::decode_checked(data, specialty_set.is_compact),
        TypeDefPrimitive::Str => {
            specialty_set.reject_compact()?;
            decode_str(data)
        }
        TypeDefPrimitive::U8 => u8::decode_checked(data, specialty_set),
        TypeDefPrimitive::U16 => u16::decode_checked(data, specialty_set),
        TypeDefPrimitive::U32 => u32::decode_checked(data, specialty_set),
        TypeDefPrimitive::U64 => u64::decode_checked(data, specialty_set),
        TypeDefPrimitive::U128 => u128::decode_checked(data, specialty_set),
        TypeDefPrimitive::U256 => BigUint::decode_checked(data, specialty_set.is_compact),
        TypeDefPrimitive::I8 => i8::decode_checked(data, specialty_set.is_compact),
        TypeDefPrimitive::I16 => i16::decode_checked(data, specialty_set.is_compact),
        TypeDefPrimitive::I32 => i32::decode_checked(data, specialty_set.is_compact),
        TypeDefPrimitive::I64 => i64::decode_checked(data, specialty_set.is_compact),
        TypeDefPrimitive::I128 => i128::decode_checked(data, specialty_set.is_compact),
        TypeDefPrimitive::I256 => BigInt::decode_checked(data, specialty_set.is_compact),
    }
}

/// Function to decode `str`.
/// `str` is encoded as a vector of utf-converteable elements, and is therefore
/// preluded by the number of elements as compact.
///
/// The function decodes only `str` part, removes already decoded part of input data Vec<u8>,
/// and returns whatever remains as DecodedOut field remaining_vector, which is processed later separately.
///
/// The function takes as arguments
/// - data (remaining Vec<u8> of data),
///
/// The function outputs the DecodedOut value in case of success.
fn decode_str(data: &mut Vec<u8>) -> Result<ParsedData, ParserError> {
    let str_length = get_compact::<u32>(data)? as usize;
    if !data.is_empty() {
        match data.get(..str_length) {
            Some(a) => {
                let text = match String::from_utf8(a.to_vec()) {
                    Ok(b) => b,
                    Err(_) => return Err(ParserError::TypeFailure("str")),
                };
                let out = ParsedData::Text(text);
                *data = data[str_length..].to_vec();
                Ok(out)
            }
            None => Err(ParserError::DataTooShort),
        }
    } else if str_length != 0 {
        Err(ParserError::DataTooShort)
    } else {
        Ok(ParsedData::Text(String::new()))
    }
}

pub fn decode_as_call_v14(
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
) -> Result<Call, SignableError> {
    let pallet_index: u8 = match data.first() {
        Some(x) => *x,
        None => return Err(SignableError::Parsing(ParserError::DataTooShort)),
    };

    *data = data[1..].to_vec();

    let mut found_calls_in_pallet_type_id: Option<UntrackedSymbol<std::any::TypeId>> = None;

    let mut found_pallet_name: Option<String> = None;
    for x in meta_v14.pallets.iter() {
        if x.index == pallet_index {
            found_pallet_name = Some(x.name.to_owned());
            if let Some(a) = &x.calls {
                found_calls_in_pallet_type_id = Some(a.ty);
            }
            break;
        }
    }

    let pallet_name = match found_pallet_name {
        Some(a) => a,
        None => return Err(SignableError::PalletNotFound(pallet_index)),
    };

    let calls_in_pallet_type = match found_calls_in_pallet_type_id {
        Some(calls_in_pallet_symbol) => {
            resolve_ty(meta_v14, calls_in_pallet_symbol.id()).map_err(SignableError::Parsing)?
        }
        None => return Err(SignableError::NoCallsInPallet(pallet_name)),
    };

    let pallet_info = Info::from_ty(calls_in_pallet_type);

    if let TypeDef::Variant(x) = calls_in_pallet_type.type_def() {
        if let SpecialtyTypeHinted::PalletSpecific(PalletSpecificItem::Call) =
            SpecialtyTypeHinted::from_path(&pallet_info.path)
        {
            let variant_data =
                decode_variant(x.variants(), data, meta_v14).map_err(SignableError::Parsing)?;
            if !data.is_empty() {
                Err(SignableError::SomeDataNotUsedCall)
            } else {
                Ok(Call(PalletSpecificData {
                    pallet_info,
                    variant_docs: variant_data.variant_docs.to_owned(),
                    pallet_name,
                    variant_name: variant_data.variant_name.to_owned(),
                    fields: variant_data.fields,
                }))
            }
        } else {
            Err(SignableError::NotACall(pallet_name))
        }
    } else {
        Err(SignableError::NotACall(pallet_name))
    }
}

/// Main decoder function.
///
/// Processes input data byte-by-byte, cutting and decoding data chunks.
///
/// This function is sometimes used recursively. Specifically, it could be
/// called on inner element(s) when decoding deals with:
///
/// - structs (`TypeDef::Composite(_)`)
/// - enums (`TypeDef::Variant(_)`)
/// - vectors (`TypeDef::Sequence(_)`)
/// - arrays (`TypeDef::Array(_)`)
/// - tuples (`TypeDef::Tuple(_)`)
/// - compacts (`TypeDef::Compact(_)`)
/// - calls and events (`SpecialtyTypeChecked::PalletSpecific{..}`)
/// - options (`SpecialtyTypeChecked:Option{..}`)
///
/// Of those, the input data itself changes on each new iteration for:
///
/// - enums (variant index gets cut off)
/// - vectors (compact vector length gets cut off)
/// - calls and events, options (also variant index gets cut off)
///
/// Thus the potential endless cycling could happen for structs, arrays, tuples,
/// and compacts. Notably, this *should not* happen in good metadata.
///
/// Decoder checks the type sequence encountered when resolving individual
/// fields, tuple elements, array elements and compacts to make sure there are
/// no repeating types that would cause an endless cycle. Cycle tracker gets
/// nullified if data gets cut, e.g. if new enum, vector, primitive or special
/// type is encountered.
pub fn decode_with_type(
    ty_input: &Ty,
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
    mut propagated: Propagated,
) -> Result<ExtendedData, ParserError> {
    let ty = match ty_input {
        Ty::Resolved(resolved) => resolved,
        Ty::Symbol(ty_symbol) => resolve_ty(meta_v14, ty_symbol.id())?,
    };
    let info_ty = Info::from_ty(ty);
    propagated.add_info(&info_ty);
    match SpecialtyTypeChecked::from_type(ty, data, meta_v14) {
        SpecialtyTypeChecked::None => match ty.type_def() {
            TypeDef::Composite(x) => {
                let field_data_set = decode_fields(x.fields(), data, meta_v14, propagated.checker)?;
                Ok(ExtendedData {
                    info: propagated.info,
                    data: ParsedData::Composite(field_data_set),
                })
            }
            TypeDef::Variant(x) => {
                propagated.reject_compact()?;
                let variant_data = decode_variant(x.variants(), data, meta_v14)?;
                Ok(ExtendedData {
                    info: propagated.info,
                    data: ParsedData::Variant(variant_data),
                })
            }
            TypeDef::Sequence(x) => {
                let number_of_elements = get_compact::<u32>(data)?;
                propagated.checker.drop_cycle_check();
                decode_elements_set(
                    x.type_param(),
                    number_of_elements,
                    data,
                    meta_v14,
                    propagated,
                )
            }
            TypeDef::Array(x) => {
                decode_elements_set(x.type_param(), x.len(), data, meta_v14, propagated)
            }
            TypeDef::Tuple(x) => {
                let inner_types_set = x.fields();
                if inner_types_set.len() > 1 {
                    propagated.reject_compact()?
                }
                let mut tuple_data_set: Vec<ExtendedData> = Vec::new();
                for inner_ty_symbol in inner_types_set.iter() {
                    let tuple_data_element = decode_with_type(
                        &Ty::Symbol(inner_ty_symbol),
                        data,
                        meta_v14,
                        Propagated::for_ty_symbol(&propagated.checker, inner_ty_symbol)?,
                    )?;
                    tuple_data_set.push(tuple_data_element);
                }
                Ok(ExtendedData {
                    info: propagated.info,
                    data: ParsedData::Tuple(tuple_data_set),
                })
            }
            TypeDef::Primitive(x) => Ok(ExtendedData {
                info: propagated.info,
                data: decode_type_def_primitive(x, data, propagated.checker.specialty_set)?,
            }),
            TypeDef::Compact(x) => {
                propagated.reject_compact()?;
                propagated.checker.specialty_set.is_compact = true;
                propagated.checker.check_id(x.type_param().id())?;
                decode_with_type(&Ty::Symbol(x.type_param()), data, meta_v14, propagated)
            }
            TypeDef::BitSequence(x) => {
                propagated.reject_compact()?;
                Ok(ExtendedData {
                    info: propagated.info,
                    data: decode_type_def_bit_sequence(x, data, meta_v14)?,
                })
            }
        },
        SpecialtyTypeChecked::AccountId32 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_account_id32(data)?,
            })
        }
        SpecialtyTypeChecked::Era => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_era(data)?,
            })
        }
        SpecialtyTypeChecked::H160 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: H160::cut_and_decode(data)?,
            })
        }
        SpecialtyTypeChecked::H256 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_h256(data, propagated.checker.specialty_set.hash256())?,
            })
        }
        SpecialtyTypeChecked::H512 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: H512::cut_and_decode(data)?,
            })
        }
        SpecialtyTypeChecked::Option(ty_symbol) => {
            propagated.reject_compact()?;
            let param_ty = resolve_ty(meta_v14, ty_symbol.id())?;
            match param_ty.type_def() {
                TypeDef::Primitive(TypeDefPrimitive::Bool) => match data.first() {
                    Some(a) => {
                        let parsed_data = match OptionBool::decode(&mut [*a].as_slice()) {
                            Ok(OptionBool(Some(true))) => {
                                ParsedData::Option(Some(Box::new(ParsedData::PrimitiveBool(true))))
                            }
                            Ok(OptionBool(Some(false))) => {
                                ParsedData::Option(Some(Box::new(ParsedData::PrimitiveBool(false))))
                            }
                            Ok(OptionBool(None)) => ParsedData::Option(None),
                            Err(_) => return Err(ParserError::UnexpectedOptionVariant),
                        };
                        *data = data[1..].to_vec();
                        Ok(ExtendedData {
                            info: propagated.info,
                            data: parsed_data,
                        })
                    }
                    None => Err(ParserError::DataTooShort),
                },
                _ => match data.first() {
                    Some(0) => {
                        *data = data[1..].to_vec();
                        Ok(ExtendedData {
                            info: propagated.info,
                            data: ParsedData::Option(None),
                        })
                    }
                    Some(1) => {
                        *data = data[1..].to_vec();
                        let extended_option_data = decode_with_type(
                            &Ty::Resolved(param_ty),
                            data,
                            meta_v14,
                            Propagated::new(),
                        )?;
                        propagated.add_info_slice(&extended_option_data.info);
                        Ok(ExtendedData {
                            info: propagated.info,
                            data: ParsedData::Option(Some(Box::new(extended_option_data.data))),
                        })
                    }
                    Some(_) => Err(ParserError::UnexpectedOptionVariant),
                    None => Err(ParserError::DataTooShort),
                },
            }
        }
        SpecialtyTypeChecked::PalletSpecific {
            pallet_name,
            pallet_info,
            variants,
            item,
        } => {
            propagated.reject_compact()?;
            let variant_data = decode_variant(variants, data, meta_v14)?;
            let pallet_specific_data = PalletSpecificData {
                pallet_info,
                variant_docs: variant_data.variant_docs.to_owned(),
                pallet_name,
                variant_name: variant_data.variant_name.to_owned(),
                fields: variant_data.fields,
            };
            match item {
                PalletSpecificItem::Call => Ok(ExtendedData {
                    info: propagated.info,
                    data: ParsedData::Call(Call(pallet_specific_data)),
                }),
                PalletSpecificItem::Event => Ok(ExtendedData {
                    info: propagated.info,
                    data: ParsedData::Event(Event(pallet_specific_data)),
                }),
            }
        }
        SpecialtyTypeChecked::Perbill => Ok(ExtendedData {
            info: propagated.info,
            data: Perbill::decode_checked(data, propagated.checker.specialty_set.is_compact)?,
        }),
        SpecialtyTypeChecked::Percent => Ok(ExtendedData {
            info: propagated.info,
            data: Percent::decode_checked(data, propagated.checker.specialty_set.is_compact)?,
        }),
        SpecialtyTypeChecked::Permill => Ok(ExtendedData {
            info: propagated.info,
            data: Permill::decode_checked(data, propagated.checker.specialty_set.is_compact)?,
        }),
        SpecialtyTypeChecked::Perquintill => Ok(ExtendedData {
            info: propagated.info,
            data: Perquintill::decode_checked(data, propagated.checker.specialty_set.is_compact)?,
        }),
        SpecialtyTypeChecked::PerU16 => Ok(ExtendedData {
            info: propagated.info,
            data: PerU16::decode_checked(data, propagated.checker.specialty_set.is_compact)?,
        }),
        SpecialtyTypeChecked::PublicEd25519 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_ed25519_public(data)?,
            })
        }
        SpecialtyTypeChecked::PublicSr25519 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_sr25519_public(data)?,
            })
        }
        SpecialtyTypeChecked::PublicEcdsa => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_ecdsa_public(data)?,
            })
        }
        SpecialtyTypeChecked::SignatureEd25519 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_ed25519_signature(data)?,
            })
        }
        SpecialtyTypeChecked::SignatureSr25519 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_sr25519_signature(data)?,
            })
        }
        SpecialtyTypeChecked::SignatureEcdsa => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                info: propagated.info,
                data: special_case_ecdsa_signature(data)?,
            })
        }
    }
}

fn decode_fields(
    fields: &[Field<PortableForm>],
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
    checker: Checker,
) -> Result<Vec<FieldData>, ParserError> {
    if fields.len() > 1 {
        checker.specialty_set.reject_compact()?;
    }
    let mut out: Vec<FieldData> = Vec::new();
    for field in fields.iter() {
        let field_name = field.name().map(|name| name.to_owned());
        let type_name = field.type_name().map(|name| name.to_owned());
        let this_field_data = decode_with_type(
            &Ty::Symbol(field.ty()),
            data,
            meta_v14,
            Propagated::for_field(&checker, field)?,
        )?;
        out.push(FieldData {
            field_name,
            type_name,
            field_docs: field.collect_docs(),
            data: this_field_data,
        })
    }
    Ok(out)
}

fn decode_elements_set(
    element: &UntrackedSymbol<std::any::TypeId>,
    number_of_elements: u32,
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
    propagated: Propagated,
) -> Result<ExtendedData, ParserError> {
    propagated.reject_compact()?;

    let husked = husk_type(element, meta_v14, propagated.checker)?;

    let data = {
        if number_of_elements == 0 {
            ParsedData::SequenceRaw(SequenceRawData {
                element_info: husked.info,
                data: Vec::new(),
            })
        } else {
            let mut out: Vec<ParsedData> = Vec::new();
            for _i in 0..number_of_elements {
                let element_extended_data = decode_with_type(
                    &Ty::Resolved(husked.ty),
                    data,
                    meta_v14,
                    Propagated::with_checker(husked.checker.clone()),
                )?;
                out.push(element_extended_data.data);
            }
            match wrap_sequence(&out) {
                Some(sequence) => ParsedData::Sequence(SequenceData {
                    element_info: husked.info,
                    data: sequence,
                }),
                None => ParsedData::SequenceRaw(SequenceRawData {
                    element_info: husked.info,
                    data: out,
                }),
            }
        }
    };
    Ok(ExtendedData {
        info: propagated.info,
        data,
    })
}

pub(crate) fn pick_variant<'a>(
    variants: &'a [Variant<PortableForm>],
    data: &[u8],
) -> Result<&'a Variant<PortableForm>, ParserError> {
    let enum_index = match data.first() {
        Some(x) => *x,
        None => return Err(ParserError::DataTooShort),
    };

    let mut found_variant = None;
    for x in variants.iter() {
        if x.index() == enum_index {
            found_variant = Some(x);
            break;
        }
    }
    match found_variant {
        Some(a) => Ok(a),
        None => Err(ParserError::UnexpectedEnumVariant),
    }
}

fn decode_variant(
    variants: &[Variant<PortableForm>],
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
) -> Result<VariantData, ParserError> {
    let found_variant = pick_variant(variants, data)?;
    *data = data[1..].to_vec();
    let variant_name = found_variant.name().to_owned();
    let variant_docs = found_variant.collect_docs();
    let fields = decode_fields(found_variant.fields(), data, meta_v14, Checker::new())?;

    Ok(VariantData {
        variant_name,
        variant_docs,
        fields,
    })
}

enum FoundBitOrder {
    Lsb0,
    Msb0,
}

const MSB0: &str = "Msb0";
const LSB0: &str = "Lsb0";

fn decode_type_def_bit_sequence(
    bit_ty: &TypeDefBitSequence<PortableForm>,
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
) -> Result<ParsedData, ParserError> {
    let cut_compact = cut_compact::<u32>(data)?;
    let bit_length_found = cut_compact.compact_found;
    let byte_length = match bit_length_found % 8 {
        0 => (bit_length_found / 8),
        _ => (bit_length_found / 8) + 1,
    } as usize;

    let into_decode = match cut_compact.start_next_unit {
        Some(start) => match data.get(..start + byte_length) {
            Some(a) => {
                let into_decode = a.to_vec();
                *data = data[start + byte_length..].to_vec();
                into_decode
            }
            None => return Err(ParserError::DataTooShort),
        },
        None => {
            let into_decode = data.to_vec();
            *data = Vec::new();
            into_decode
        }
    };

    // BitOrder
    let bitorder_type = resolve_ty(meta_v14, bit_ty.bit_order_type().id())?;
    let bitorder = match bitorder_type.type_def() {
        TypeDef::Composite(_) => match bitorder_type.path().ident() {
            Some(x) => match x.as_str() {
                LSB0 => FoundBitOrder::Lsb0,
                MSB0 => FoundBitOrder::Msb0,
                _ => return Err(ParserError::NotBitOrderType),
            },
            None => return Err(ParserError::NotBitOrderType),
        },
        _ => return Err(ParserError::NotBitOrderType),
    };

    // BitStore
    let bitstore_type = resolve_ty(meta_v14, bit_ty.bit_store_type().id())?;

    match bitstore_type.type_def() {
        TypeDef::Primitive(TypeDefPrimitive::U8) => match bitorder {
            FoundBitOrder::Lsb0 => {
                <BitVec<u8, Lsb0>>::decode(&mut &into_decode[..]).map(ParsedData::BitVecU8Lsb0)
            }
            FoundBitOrder::Msb0 => {
                <BitVec<u8, Msb0>>::decode(&mut &into_decode[..]).map(ParsedData::BitVecU8Msb0)
            }
        },
        TypeDef::Primitive(TypeDefPrimitive::U16) => {
            match bitorder {
                FoundBitOrder::Lsb0 => <BitVec<u16, Lsb0>>::decode(&mut &into_decode[..])
                    .map(ParsedData::BitVecU16Lsb0),
                FoundBitOrder::Msb0 => <BitVec<u16, Msb0>>::decode(&mut &into_decode[..])
                    .map(ParsedData::BitVecU16Msb0),
            }
        }
        TypeDef::Primitive(TypeDefPrimitive::U32) => {
            match bitorder {
                FoundBitOrder::Lsb0 => <BitVec<u32, Lsb0>>::decode(&mut &into_decode[..])
                    .map(ParsedData::BitVecU32Lsb0),
                FoundBitOrder::Msb0 => <BitVec<u32, Msb0>>::decode(&mut &into_decode[..])
                    .map(ParsedData::BitVecU32Msb0),
            }
        }
        TypeDef::Primitive(TypeDefPrimitive::U64) => {
            match bitorder {
                FoundBitOrder::Lsb0 => <BitVec<u64, Lsb0>>::decode(&mut &into_decode[..])
                    .map(ParsedData::BitVecU64Lsb0),
                FoundBitOrder::Msb0 => <BitVec<u64, Msb0>>::decode(&mut &into_decode[..])
                    .map(ParsedData::BitVecU64Msb0),
            }
        }
        _ => return Err(ParserError::NotBitStoreType),
    }
    .map_err(|_| ParserError::TypeFailure("BitVec"))
}

struct HuskedType<'a> {
    info: Vec<Info>,
    checker: Checker,
    ty: &'a Type<PortableForm>,
}

fn husk_type<'a>(
    entry_symbol: &'a UntrackedSymbol<std::any::TypeId>,
    meta_v14: &'a RuntimeMetadataV14,
    mut checker: Checker,
) -> Result<HuskedType<'a>, ParserError> {
    let entry_symbol_id = entry_symbol.id();
    checker.check_id(entry_symbol_id)?;
    checker.specialty_set = SpecialtySet {
        hint: Hint::None,
        is_compact: false,
    };

    let mut ty = resolve_ty(meta_v14, entry_symbol_id)?;
    let mut info: Vec<Info> = Vec::new();

    loop {
        let info_ty = Info::from_ty(ty);
        if !info_ty.is_empty() {
            info.push(info_ty)
        }

        if let SpecialtyTypeHinted::None = SpecialtyTypeHinted::from_path(ty.path()) {
            match ty.type_def() {
                TypeDef::Composite(x) => {
                    let fields = x.fields();
                    if fields.len() == 1 {
                        let id = fields[0].ty().id();
                        checker.check_id(id)?;
                        ty = resolve_ty(meta_v14, id)?;
                        if let Hint::None = checker.specialty_set.hint {
                            checker.specialty_set.hint = Hint::from_field(&fields[0])
                        }
                    } else {
                        break;
                    }
                }
                TypeDef::Compact(x) => {
                    checker.specialty_set.reject_compact()?;
                    checker.specialty_set.is_compact = true;
                    let id = x.type_param().id();
                    checker.check_id(id)?;
                    ty = resolve_ty(meta_v14, id)?;
                }
                _ => break,
            }
        } else {
            break;
        }
    }

    Ok(HuskedType { info, checker, ty })
}

pub enum Ty<'a> {
    Resolved(&'a Type<PortableForm>),
    Symbol(&'a UntrackedSymbol<std::any::TypeId>),
}

fn resolve_ty(meta_v14: &RuntimeMetadataV14, id: u32) -> Result<&Type<PortableForm>, ParserError> {
    match meta_v14.types.resolve(id) {
        Some(a) => Ok(a),
        None => Err(ParserError::V14TypeNotResolved(id)),
    }
}
