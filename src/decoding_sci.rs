//! Decode data using [`RuntimeMetadataV14`].
use bitvec::prelude::{BitVec, Lsb0, Msb0};
use frame_metadata::v14::RuntimeMetadataV14;
use num_bigint::{BigInt, BigUint};
use parity_scale_codec::{Decode, OptionBool};
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, Field, PortableRegistry, Type, TypeDef,
    TypeDefBitSequence, TypeDefPrimitive, Variant,
};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};
use sp_core::{crypto::AccountId32, H160, H512};

use crate::cards::{
    Call, Documented, Event, ExtendedData, FieldData, Info, PalletSpecificData, ParsedData,
    SequenceData, SequenceRawData, VariantData,
};
use crate::compacts::{find_compact, get_compact};
use crate::error::{ParserError, SignableError};
use crate::propagated::{Checker, Propagated, SpecialtySet};
use crate::special_indicators::{
    Hint, PalletSpecificItem, SpecialtyTypeChecked, SpecialtyTypeHinted,
};
use crate::special_types::{
    special_case_era, special_case_h256, wrap_sequence, CheckCompact, UnsignedInteger,
};
use crate::Positions;

/// Finalize parsing of primitives (variants of [`TypeDefPrimitive`]).
///
/// Current parser position gets changed. Propagated to this point
/// [`SpecialtySet`] is used.
fn decode_type_def_primitive(
    found_ty: &TypeDefPrimitive,
    data: &[u8],
    position: &mut usize,
    specialty_set: SpecialtySet,
) -> Result<ParsedData, ParserError> {
    match found_ty {
        TypeDefPrimitive::Bool => {
            bool::parse_check_compact(data, position, specialty_set.is_compact)
        }
        TypeDefPrimitive::Char => {
            char::parse_check_compact(data, position, specialty_set.is_compact)
        }
        TypeDefPrimitive::Str => {
            specialty_set.reject_compact()?;
            decode_str(data, position)
        }
        TypeDefPrimitive::U8 => u8::parse_unsigned_integer(data, position, specialty_set),
        TypeDefPrimitive::U16 => u16::parse_unsigned_integer(data, position, specialty_set),
        TypeDefPrimitive::U32 => u32::parse_unsigned_integer(data, position, specialty_set),
        TypeDefPrimitive::U64 => u64::parse_unsigned_integer(data, position, specialty_set),
        TypeDefPrimitive::U128 => u128::parse_unsigned_integer(data, position, specialty_set),
        TypeDefPrimitive::U256 => {
            BigUint::parse_check_compact(data, position, specialty_set.is_compact)
        }
        TypeDefPrimitive::I8 => i8::parse_check_compact(data, position, specialty_set.is_compact),
        TypeDefPrimitive::I16 => i16::parse_check_compact(data, position, specialty_set.is_compact),
        TypeDefPrimitive::I32 => i32::parse_check_compact(data, position, specialty_set.is_compact),
        TypeDefPrimitive::I64 => i64::parse_check_compact(data, position, specialty_set.is_compact),
        TypeDefPrimitive::I128 => {
            i128::parse_check_compact(data, position, specialty_set.is_compact)
        }
        TypeDefPrimitive::I256 => {
            BigInt::parse_check_compact(data, position, specialty_set.is_compact)
        }
    }
}

/// Decode `str`.
///
/// `str` is a `Vec<u8>` with utf-convertible elements, and is decoded as a
/// vector (compact of length precedes the data).
///
/// Current parser position gets changed.
fn decode_str(data: &[u8], position: &mut usize) -> Result<ParsedData, ParserError> {
    let str_length = get_compact::<u32>(data, position)? as usize;
    if *position != data.len() {
        match data.get(..str_length) {
            Some(a) => {
                let text = match String::from_utf8(a.to_vec()) {
                    Ok(b) => b,
                    Err(_) => return Err(ParserError::TypeFailure("str")),
                };
                let out = ParsedData::Text(text);
                *position += str_length;
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

/// Parse call part of the signable transaction with provided `V14` metadata.
///
/// Call data is contained within the provided [`Positions`] determined
/// elsewhere. Call data is expected to have proper call structure and to be
/// decoded completely, with no data left.
///
/// The first `u8` element of the call data is a pallet index, the type within
/// corresponding `PalletCallMetadata` is expected to be an enum with
/// pallet-specific calls. If the pallet-call pattern is not observed, an error
/// occurs.
pub fn decode_as_call(
    data: &[u8],
    positions: Positions,
    meta_v14: &RuntimeMetadataV14,
) -> Result<Call, SignableError> {
    let mut position = positions.call_start();

    let pallet_index: u8 = match data.get(position) {
        Some(x) => *x,
        None => return Err(SignableError::Parsing(ParserError::DataTooShort)),
    };

    position += 1;

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
        Some(calls_in_pallet_symbol) => resolve_ty(&meta_v14.types, calls_in_pallet_symbol.id())
            .map_err(SignableError::Parsing)?,
        None => return Err(SignableError::NoCallsInPallet(pallet_name)),
    };

    let pallet_info = Info::from_ty(calls_in_pallet_type);

    if let TypeDef::Variant(x) = calls_in_pallet_type.type_def() {
        if let SpecialtyTypeHinted::PalletSpecific(PalletSpecificItem::Call) =
            SpecialtyTypeHinted::from_path(&pallet_info.path)
        {
            let variant_data = decode_variant(x.variants(), data, &mut position, &meta_v14.types)
                .map_err(SignableError::Parsing)?;
            if position != positions.extensions_start() {
                Err(SignableError::SomeDataNotUsedCall {
                    from: position,
                    to: positions.extensions_start(),
                })
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

/// General decoder function. Parse part of data as [`Ty`].
///
/// Processes input data byte-by-byte, cutting and decoding data chunks. Current
/// parser position gets changed.
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
/// Of those, the parser position changes on each new iteration for:
///
/// - enums (variant index is passed)
/// - vectors (compact vector length indicator is passed)
/// - calls and events, options (also variant index is passed)
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
    data: &[u8],
    position: &mut usize,
    registry: &PortableRegistry,
    mut propagated: Propagated,
) -> Result<ExtendedData, ParserError> {
    let ty = match ty_input {
        Ty::Resolved(resolved) => resolved,
        Ty::Symbol(ty_symbol) => resolve_ty(registry, ty_symbol.id())?,
    };
    let info_ty = Info::from_ty(ty);
    propagated.add_info(&info_ty);
    match SpecialtyTypeChecked::from_type(ty, data, position, registry) {
        SpecialtyTypeChecked::None => match ty.type_def() {
            TypeDef::Composite(x) => {
                let field_data_set =
                    decode_fields(x.fields(), data, position, registry, propagated.checker)?;
                Ok(ExtendedData {
                    data: ParsedData::Composite(field_data_set),
                    info: propagated.info,
                })
            }
            TypeDef::Variant(x) => {
                propagated.reject_compact()?;
                let variant_data = decode_variant(x.variants(), data, position, registry)?;
                Ok(ExtendedData {
                    data: ParsedData::Variant(variant_data),
                    info: propagated.info,
                })
            }
            TypeDef::Sequence(x) => {
                let number_of_elements = get_compact::<u32>(data, position)?;
                propagated.checker.drop_cycle_check();
                decode_elements_set(
                    x.type_param(),
                    number_of_elements,
                    data,
                    position,
                    registry,
                    propagated,
                )
            }
            TypeDef::Array(x) => decode_elements_set(
                x.type_param(),
                x.len(),
                data,
                position,
                registry,
                propagated,
            ),
            TypeDef::Tuple(x) => {
                let inner_types_set = x.fields();
                if inner_types_set.len() > 1 {
                    propagated.reject_compact()?;
                    propagated.forget_hint();
                }
                let mut tuple_data_set: Vec<ExtendedData> = Vec::new();
                for inner_ty_symbol in inner_types_set.iter() {
                    let tuple_data_element = decode_with_type(
                        &Ty::Symbol(inner_ty_symbol),
                        data,
                        position,
                        registry,
                        Propagated::for_ty_symbol(&propagated.checker, inner_ty_symbol)?,
                    )?;
                    tuple_data_set.push(tuple_data_element);
                }
                Ok(ExtendedData {
                    data: ParsedData::Tuple(tuple_data_set),
                    info: propagated.info,
                })
            }
            TypeDef::Primitive(x) => Ok(ExtendedData {
                data: decode_type_def_primitive(
                    x,
                    data,
                    position,
                    propagated.checker.specialty_set,
                )?,
                info: propagated.info,
            }),
            TypeDef::Compact(x) => {
                propagated.reject_compact()?;
                propagated.checker.specialty_set.is_compact = true;
                propagated.checker.check_id(x.type_param().id())?;
                decode_with_type(
                    &Ty::Symbol(x.type_param()),
                    data,
                    position,
                    registry,
                    propagated,
                )
            }
            TypeDef::BitSequence(x) => {
                propagated.reject_compact()?;
                Ok(ExtendedData {
                    data: decode_type_def_bit_sequence(x, data, position, registry)?,
                    info: propagated.info,
                })
            }
        },
        SpecialtyTypeChecked::AccountId32 => Ok(ExtendedData {
            data: AccountId32::parse_check_compact(data, position, propagated.is_compact())?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Era => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                data: special_case_era(data, position)?,
                info: propagated.info,
            })
        }
        SpecialtyTypeChecked::H160 => Ok(ExtendedData {
            data: H160::parse_check_compact(data, position, propagated.is_compact())?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::H256 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                data: special_case_h256(
                    data,
                    position,
                    propagated.checker.specialty_set.hash256(),
                )?,
                info: propagated.info,
            })
        }
        SpecialtyTypeChecked::H512 => Ok(ExtendedData {
            data: H512::parse_check_compact(data, position, propagated.is_compact())?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Option(ty_symbol) => {
            propagated.reject_compact()?;
            let param_ty = resolve_ty(registry, ty_symbol.id())?;
            match param_ty.type_def() {
                TypeDef::Primitive(TypeDefPrimitive::Bool) => match data.get(*position) {
                    Some(a) => {
                        let parsed_data = match OptionBool::decode(&mut [*a].as_slice()) {
                            Ok(OptionBool(Some(true))) => {
                                ParsedData::Option(Some(Box::new(ParsedData::PrimitiveBool(true))))
                            }
                            Ok(OptionBool(Some(false))) => {
                                ParsedData::Option(Some(Box::new(ParsedData::PrimitiveBool(false))))
                            }
                            Ok(OptionBool(None)) => ParsedData::Option(None),
                            Err(_) => {
                                return Err(ParserError::UnexpectedOptionVariant {
                                    position: *position,
                                })
                            }
                        };
                        *position += 1;
                        Ok(ExtendedData {
                            data: parsed_data,
                            info: propagated.info,
                        })
                    }
                    None => Err(ParserError::DataTooShort),
                },
                _ => match data.get(*position) {
                    Some(0) => {
                        *position += 1;
                        Ok(ExtendedData {
                            data: ParsedData::Option(None),
                            info: propagated.info,
                        })
                    }
                    Some(1) => {
                        *position += 1;
                        let extended_option_data = decode_with_type(
                            &Ty::Resolved(param_ty),
                            data,
                            position,
                            registry,
                            Propagated::new(),
                        )?;
                        propagated.add_info_slice(&extended_option_data.info);
                        Ok(ExtendedData {
                            data: ParsedData::Option(Some(Box::new(extended_option_data.data))),
                            info: propagated.info,
                        })
                    }
                    Some(_) => Err(ParserError::UnexpectedOptionVariant {
                        position: *position,
                    }),
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
            let variant_data = decode_variant(variants, data, position, registry)?;
            let pallet_specific_data = PalletSpecificData {
                pallet_info,
                variant_docs: variant_data.variant_docs.to_owned(),
                pallet_name,
                variant_name: variant_data.variant_name.to_owned(),
                fields: variant_data.fields,
            };
            match item {
                PalletSpecificItem::Call => Ok(ExtendedData {
                    data: ParsedData::Call(Call(pallet_specific_data)),
                    info: propagated.info,
                }),
                PalletSpecificItem::Event => Ok(ExtendedData {
                    data: ParsedData::Event(Event(pallet_specific_data)),
                    info: propagated.info,
                }),
            }
        }
        SpecialtyTypeChecked::Perbill => Ok(ExtendedData {
            data: Perbill::parse_check_compact(data, position, propagated.is_compact())?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Percent => Ok(ExtendedData {
            data: Percent::parse_check_compact(data, position, propagated.is_compact())?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Permill => Ok(ExtendedData {
            data: Permill::parse_check_compact(data, position, propagated.is_compact())?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Perquintill => Ok(ExtendedData {
            data: Perquintill::parse_check_compact(data, position, propagated.is_compact())?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PerU16 => Ok(ExtendedData {
            data: PerU16::parse_check_compact(data, position, propagated.is_compact())?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PublicEd25519 => Ok(ExtendedData {
            data: sp_core::ed25519::Public::parse_check_compact(
                data,
                position,
                propagated.is_compact(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PublicSr25519 => Ok(ExtendedData {
            data: sp_core::sr25519::Public::parse_check_compact(
                data,
                position,
                propagated.is_compact(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PublicEcdsa => Ok(ExtendedData {
            data: sp_core::ecdsa::Public::parse_check_compact(
                data,
                position,
                propagated.is_compact(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::SignatureEd25519 => Ok(ExtendedData {
            data: sp_core::ed25519::Signature::parse_check_compact(
                data,
                position,
                propagated.is_compact(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::SignatureSr25519 => Ok(ExtendedData {
            data: sp_core::sr25519::Signature::parse_check_compact(
                data,
                position,
                propagated.is_compact(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::SignatureEcdsa => Ok(ExtendedData {
            data: sp_core::ecdsa::Signature::parse_check_compact(
                data,
                position,
                propagated.is_compact(),
            )?,
            info: propagated.info,
        }),
    }
}

/// Parse part of data as a set of [`Field`]s. Used for structs, enums and call
/// decoding.
///
/// Current parser position gets changed.
fn decode_fields(
    fields: &[Field<PortableForm>],
    data: &[u8],
    position: &mut usize,
    registry: &PortableRegistry,
    mut checker: Checker,
) -> Result<Vec<FieldData>, ParserError> {
    if fields.len() > 1 {
        // Only single-field structs can be processed as a compact.
        // Note: compact flag was already checked in enum processing at this
        // point.
        checker.reject_compact()?;

        // `Hint` remains relevant only if single-field struct is processed.
        // Note: checker gets renewed when fields of enum are processed.
        checker.forget_hint();
    }
    let mut out: Vec<FieldData> = Vec::new();
    for field in fields.iter() {
        let field_name = field.name().map(|name| name.to_owned());
        let type_name = field.type_name().map(|name| name.to_owned());
        let this_field_data = decode_with_type(
            &Ty::Symbol(field.ty()),
            data,
            position,
            registry,
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

/// Parse part of data as a known number of identical elements. Used for vectors
/// and arrays.
///
/// Current parser position gets changed.
fn decode_elements_set(
    element: &UntrackedSymbol<std::any::TypeId>,
    number_of_elements: u32,
    data: &[u8],
    position: &mut usize,
    registry: &PortableRegistry,
    propagated: Propagated,
) -> Result<ExtendedData, ParserError> {
    propagated.reject_compact()?;

    let husked = husk_type(element, registry, propagated.checker)?;

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
                    position,
                    registry,
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
        data,
        info: propagated.info,
    })
}

/// Select an enum variant based on data.
///
/// First data `u8` element is `index` of [`Variant`].
///
/// Does not modify the input.
pub(crate) fn pick_variant<'a>(
    variants: &'a [Variant<PortableForm>],
    data: &[u8],
    position: usize,
) -> Result<&'a Variant<PortableForm>, ParserError> {
    let enum_index = match data.get(position) {
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
        None => Err(ParserError::UnexpectedEnumVariant { position }),
    }
}

/// Parse part of data as a variant. Used for enums and call decoding.
///
/// Current parser position gets changed.
fn decode_variant(
    variants: &[Variant<PortableForm>],
    data: &[u8],
    position: &mut usize,
    registry: &PortableRegistry,
) -> Result<VariantData, ParserError> {
    let found_variant = pick_variant(variants, data, *position)?;
    *position += 1;
    let variant_name = found_variant.name().to_owned();
    let variant_docs = found_variant.collect_docs();
    let fields = decode_fields(
        found_variant.fields(),
        data,
        position,
        registry,
        Checker::new(),
    )?;

    Ok(VariantData {
        variant_name,
        variant_docs,
        fields,
    })
}

/// `BitOrder` as determined by the `bit_order_type` for [`TypeDefBitSequence`].
enum FoundBitOrder {
    Lsb0,
    Msb0,
}

/// [`Type`]-associated [`Path`](scale_info::Path) `ident` for
/// [bitvec::order::Msb0].
const MSB0: &str = "Msb0";

/// [`Type`]-associated [`Path`](scale_info::Path) `ident` for
/// [bitvec::order::Lsb0].
const LSB0: &str = "Lsb0";

/// Parse part of data as a bitvec.
fn decode_type_def_bit_sequence(
    bit_ty: &TypeDefBitSequence<PortableForm>,
    data: &[u8],
    position: &mut usize,
    registry: &PortableRegistry,
) -> Result<ParsedData, ParserError> {
    let found_compact = find_compact::<u32>(data, *position)?;
    let bit_length_found = found_compact.compact;
    let byte_length = match bit_length_found % 8 {
        0 => bit_length_found / 8,
        _ => (bit_length_found / 8) + 1,
    } as usize;

    let into_decode = match data.get(*position..found_compact.start_next_unit + byte_length) {
        Some(a) => {
            let into_decode = a.to_vec();
            *position = found_compact.start_next_unit + byte_length;
            into_decode
        }
        None => return Err(ParserError::DataTooShort),
    };

    // BitOrder
    let bitorder_type = resolve_ty(registry, bit_ty.bit_order_type().id())?;
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
    let bitstore_type = resolve_ty(registry, bit_ty.bit_store_type().id())?;

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

/// Type of set element, resolved as completely as possible.
///
/// Elements in set (vector or array) could have complex solvable descriptions.
///
/// Element [`Info`] is collected while resolving the type. No identical
/// [`Type`] `id`s are expected to be encountered (these are collected and
/// checked in [`Checker`]), otherwise the resolving would go indefinitely.
struct HuskedType<'a> {
    info: Vec<Info>,
    checker: Checker,
    ty: &'a Type<PortableForm>,
}

/// Resolve [`Type`] of set element.
///
/// Compact and single-field structs are resolved into corresponding inner
/// types. All available [`Info`] is collected.
fn husk_type<'a>(
    entry_symbol: &'a UntrackedSymbol<std::any::TypeId>,
    registry: &'a PortableRegistry,
    mut checker: Checker,
) -> Result<HuskedType<'a>, ParserError> {
    let entry_symbol_id = entry_symbol.id();
    checker.check_id(entry_symbol_id)?;
    checker.specialty_set = SpecialtySet {
        hint: Hint::None,
        is_compact: false,
    };

    let mut ty = resolve_ty(registry, entry_symbol_id)?;
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
                        ty = resolve_ty(registry, id)?;
                        if let Hint::None = checker.specialty_set.hint {
                            checker.specialty_set.hint = Hint::from_field(&fields[0])
                        }
                    } else {
                        break;
                    }
                }
                TypeDef::Compact(x) => {
                    checker.reject_compact()?;
                    checker.specialty_set.is_compact = true;
                    let id = x.type_param().id();
                    checker.check_id(id)?;
                    ty = resolve_ty(registry, id)?;
                }
                _ => break,
            }
        } else {
            break;
        }
    }

    Ok(HuskedType { info, checker, ty })
}

/// Type information used for parsing.
pub enum Ty<'a> {
    /// Type is already resolved in metadata `Registry`.
    Resolved(&'a Type<PortableForm>),

    /// Type is not yet resolved.
    Symbol(&'a UntrackedSymbol<std::any::TypeId>),
}

/// Resolve type id in `V14` metadata types `Registry`.
pub(crate) fn resolve_ty(
    registry: &PortableRegistry,
    id: u32,
) -> Result<&Type<PortableForm>, ParserError> {
    match registry.resolve(id) {
        Some(a) => Ok(a),
        None => Err(ParserError::V14TypeNotResolved(id)),
    }
}
