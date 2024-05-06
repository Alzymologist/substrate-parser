//! Decode types and calls using metadata with in-built type descriptors.
#[cfg(any(target_pointer_width = "32", test))]
use bitvec::prelude::BitOrder;
use bitvec::prelude::{BitVec, Lsb0, Msb0};
#[cfg(any(target_pointer_width = "32", test))]
use external_memory_tools::BufferError;
use external_memory_tools::{AddressableBuffer, ExternalMemory};
use num_bigint::{BigInt, BigUint};
use parity_scale_codec::DecodeAll;
use primitive_types::{H160, H512};
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, Field, Type, TypeDef, TypeDefBitSequence,
    TypeDefPrimitive, Variant,
};
use sp_arithmetic::{PerU16, Perbill, Percent, Permill, Perquintill};
use substrate_crypto_light::{
    common::AccountId32,
    ecdsa::{Public as PublicEcdsa, Signature as SignatureEcdsa},
    ed25519::{Public as PublicEd25519, Signature as SignatureEd25519},
    sr25519::{Public as PublicSr25519, Signature as SignatureSr25519},
};

use crate::std::{borrow::ToOwned, string::String, vec::Vec};

#[cfg(not(feature = "std"))]
use core::{any::TypeId, mem::size_of};
#[cfg(feature = "std")]
use std::{any::TypeId, mem::size_of};

use crate::cards::{
    Call, Documented, Event, ExtendedData, FieldData, Info, PalletSpecificData, ParsedData,
    SequenceData, SequenceRawData, VariantData,
};
use crate::compacts::{find_compact, get_compact};
use crate::error::{ParserError, RegistryError, RegistryInternalError, SignableError};
use crate::propagated::{Checker, Propagated, SpecialtySet};
use crate::special_indicators::{
    Hint, PalletSpecificItem, SpecialtyTypeChecked, SpecialtyTypeHinted, ENUM_INDEX_ENCODED_LEN,
};
use crate::special_types::{
    special_case_era, special_case_h256, wrap_sequence, CheckCompact, UnsignedInteger,
};
use crate::traits::{AsMetadata, ResolveType};
use crate::MarkedData;

/// Finalize parsing of primitives (variants of [`TypeDefPrimitive`]).
///
/// Current parser position gets changed. Propagated to this point
/// [`SpecialtySet`] is used.
pub fn decode_type_def_primitive<B, E>(
    found_ty: &TypeDefPrimitive,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    specialty_set: SpecialtySet,
) -> Result<ParsedData, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
{
    match found_ty {
        TypeDefPrimitive::Bool => {
            bool::parse_check_compact::<B, E>(data, ext_memory, position, specialty_set.compact_at)
        }
        TypeDefPrimitive::Char => {
            char::parse_check_compact::<B, E>(data, ext_memory, position, specialty_set.compact_at)
        }
        TypeDefPrimitive::Str => {
            specialty_set.reject_compact()?;
            decode_str::<B, E>(data, ext_memory, position, specialty_set.hint)
        }
        TypeDefPrimitive::U8 => {
            u8::parse_unsigned_integer::<B, E>(data, ext_memory, position, specialty_set)
        }
        TypeDefPrimitive::U16 => {
            u16::parse_unsigned_integer::<B, E>(data, ext_memory, position, specialty_set)
        }
        TypeDefPrimitive::U32 => {
            u32::parse_unsigned_integer::<B, E>(data, ext_memory, position, specialty_set)
        }
        TypeDefPrimitive::U64 => {
            u64::parse_unsigned_integer::<B, E>(data, ext_memory, position, specialty_set)
        }
        TypeDefPrimitive::U128 => {
            u128::parse_unsigned_integer::<B, E>(data, ext_memory, position, specialty_set)
        }
        TypeDefPrimitive::U256 => BigUint::parse_check_compact::<B, E>(
            data,
            ext_memory,
            position,
            specialty_set.compact_at,
        ),
        TypeDefPrimitive::I8 => {
            i8::parse_check_compact::<B, E>(data, ext_memory, position, specialty_set.compact_at)
        }
        TypeDefPrimitive::I16 => {
            i16::parse_check_compact::<B, E>(data, ext_memory, position, specialty_set.compact_at)
        }
        TypeDefPrimitive::I32 => {
            i32::parse_check_compact::<B, E>(data, ext_memory, position, specialty_set.compact_at)
        }
        TypeDefPrimitive::I64 => {
            i64::parse_check_compact::<B, E>(data, ext_memory, position, specialty_set.compact_at)
        }
        TypeDefPrimitive::I128 => {
            i128::parse_check_compact::<B, E>(data, ext_memory, position, specialty_set.compact_at)
        }
        TypeDefPrimitive::I256 => BigInt::parse_check_compact::<B, E>(
            data,
            ext_memory,
            position,
            specialty_set.compact_at,
        ),
    }
}

/// Decode `str`.
///
/// `str` is a `Vec<u8>` with utf-convertible elements, and is decoded as a
/// vector (compact of length precedes the data).
///
/// Current parser position gets changed.
fn decode_str<B, E>(
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    hint: Hint,
) -> Result<ParsedData, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
{
    let found_compact = find_compact::<u32, B, E>(data, ext_memory, *position)?;
    let str_length = found_compact.compact as usize;
    let text_start = found_compact.start_next_unit;
    let into_string = data.read_slice(ext_memory, text_start, str_length)?;
    let text = match String::from_utf8(into_string.as_ref().to_vec()) {
        Ok(b) => b,
        Err(_) => {
            return Err(ParserError::TypeFailure {
                position: *position,
                ty: "str",
            })
        }
    };
    let specialty = hint.string();
    let out = ParsedData::Text { text, specialty };
    *position = text_start + str_length;
    Ok(out)
}

/// Parse call part of the signable transaction [`MarkedData`] using provided
/// metadata.
///
/// Call data is expected to have proper call structure and to be decoded
/// completely, with no data left.
///
/// Entry point for call decoding is `call_ty`, describing all available pallets
/// for the chain. Type corresponding to `call_ty` is expected to be an enum
/// with call-associated `Path` identifier
/// [`CALL`](crate::special_indicators::CALL), and the selected variant is
/// expected to have a single field, also and enum by type, also having
/// call-associated `Path` identifier and corresponding to all calls within
/// selected pallet. If the pallet-call pattern is not observed, an error
/// occurs.
pub fn decode_as_call<B, E, M>(
    marked_data: &MarkedData<B, E, M>,
    ext_memory: &mut E,
    metadata: &M,
) -> Result<Call, SignableError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let data = marked_data.data_no_extensions();
    let mut position = marked_data.call_start();

    let call = decode_as_call_unmarked(&data, &mut position, ext_memory, metadata)?;
    if position != marked_data.extensions_start() {
        Err(SignableError::SomeDataNotUsedCall {
            from: position,
            to: marked_data.extensions_start(),
        })
    } else {
        Ok(call)
    }
}

/// Parse call part of the signable transaction using provided metadata.
///
/// Entry point for call decoding is `call_ty`, describing all available pallets
/// for the chain. Type corresponding to `call_ty` is expected to be an enum
/// with call-associated `Path` identifier
/// [`CALL`](crate::special_indicators::CALL), and the selected variant is
/// expected to have a single field, also and enum by type, also having
/// call-associated `Path` identifier and corresponding to all calls within
/// selected pallet. If the pallet-call pattern is not observed, an error
/// occurs.
pub fn decode_as_call_unmarked<B, E, M>(
    data: &B,
    position: &mut usize,
    ext_memory: &mut E,
    metadata: &M,
) -> Result<Call, SignableError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let call_ty = metadata.call_ty().map_err(SignableError::MetaStructure)?;

    let call_extended_data = decode_with_type::<B, E, M>(
        &Ty::Symbol(&call_ty),
        data,
        ext_memory,
        position,
        &metadata.types(),
        Propagated::new(),
    )?;
    if let ParsedData::Call(call) = call_extended_data.data {
        Ok(call)
    } else {
        Err(SignableError::NotACall(call_ty.id))
    }
}

/// General decoder function. Parse part of data as [`Ty`].
///
/// Processes input data byte-by-byte, starting at given position, selecting and
/// decoding data chunks. Position changes as decoding proceeds.
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
///
/// Of those, the parser position changes on each new iteration for:
///
/// - enums (variant index is passed)
/// - vectors (compact vector length indicator is passed)
/// - calls and events (also variant index is passed)
///
/// In empty enums there are no inner types, therefore cycling is impossible.
///
/// Thus the potential endless cycling could happen for structs, arrays, tuples,
/// and compacts. Notably, this *should not* happen in good metadata.
///
/// Decoder checks the type sequence encountered when resolving individual
/// fields, tuple elements, array elements and compacts to make sure there are
/// no repeating types that would cause an endless cycle. Cycle tracker gets
/// nullified if the parser position gets changed, e.g. if new enum, vector,
/// primitive or special type is encountered.
pub fn decode_with_type<B, E, M>(
    ty_input: &Ty,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    mut propagated: Propagated,
) -> Result<ExtendedData, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let (ty, id) = match ty_input {
        Ty::Resolved(resolved_ty) => (resolved_ty.ty.to_owned(), resolved_ty.id),
        Ty::Symbol(ty_symbol) => (registry.resolve_ty(ty_symbol.id, ext_memory)?, ty_symbol.id),
    };
    let info_ty = Info::from_ty(&ty);
    propagated.add_info(&info_ty);
    match SpecialtyTypeChecked::from_type::<B, E, M>(&ty, data, ext_memory, position, registry) {
        SpecialtyTypeChecked::None => match &ty.type_def {
            TypeDef::Composite(x) => {
                let field_data_set = decode_fields::<B, E, M>(
                    &x.fields,
                    data,
                    ext_memory,
                    position,
                    registry,
                    propagated.checker,
                )?;
                Ok(ExtendedData {
                    data: ParsedData::Composite(field_data_set),
                    info: propagated.info,
                })
            }
            TypeDef::Variant(x) => {
                propagated.reject_compact()?;
                if !x.variants.is_empty() {
                    let variant_data = decode_variant::<B, E, M>(
                        &x.variants,
                        data,
                        ext_memory,
                        position,
                        registry,
                    )?;
                    Ok(ExtendedData {
                        data: ParsedData::Variant(variant_data),
                        info: propagated.info,
                    })
                } else {
                    Ok(ExtendedData {
                        data: ParsedData::EmptyEnum,
                        info: propagated.info,
                    })
                }
            }
            TypeDef::Sequence(x) => {
                let number_of_elements = get_compact::<u32, B, E>(data, ext_memory, position)?;
                propagated.checker.drop_cycle_check();
                decode_elements_set::<B, E, M>(
                    &x.type_param,
                    number_of_elements,
                    data,
                    ext_memory,
                    position,
                    registry,
                    propagated,
                )
            }
            TypeDef::Array(x) => decode_elements_set::<B, E, M>(
                &x.type_param,
                x.len,
                data,
                ext_memory,
                position,
                registry,
                propagated,
            ),
            TypeDef::Tuple(x) => {
                if x.fields.len() > 1 {
                    propagated.reject_compact()?;
                    propagated.forget_hint();
                }
                let mut tuple_data_set: Vec<ExtendedData> = Vec::new();
                for inner_ty_symbol in x.fields.iter() {
                    let id = inner_ty_symbol.id;
                    let ty = registry.resolve_ty(id, ext_memory)?;
                    let tuple_data_element = decode_with_type::<B, E, M>(
                        &Ty::Resolved(ResolvedTy {
                            ty: ty.to_owned(),
                            id,
                        }),
                        data,
                        ext_memory,
                        position,
                        registry,
                        Propagated::for_ty(&propagated.checker, &ty, id)?,
                    )?;
                    tuple_data_set.push(tuple_data_element);
                }
                Ok(ExtendedData {
                    data: ParsedData::Tuple(tuple_data_set),
                    info: propagated.info,
                })
            }
            TypeDef::Primitive(x) => Ok(ExtendedData {
                data: decode_type_def_primitive::<B, E>(
                    x,
                    data,
                    ext_memory,
                    position,
                    propagated.checker.specialty_set,
                )?,
                info: propagated.info,
            }),
            TypeDef::Compact(x) => {
                propagated.reject_compact()?;
                propagated.checker.specialty_set.compact_at = Some(id);
                propagated.checker.check_id(x.type_param.id)?;
                decode_with_type::<B, E, M>(
                    &Ty::Symbol(&x.type_param),
                    data,
                    ext_memory,
                    position,
                    registry,
                    propagated,
                )
            }
            TypeDef::BitSequence(x) => {
                propagated.reject_compact()?;
                Ok(ExtendedData {
                    data: decode_type_def_bit_sequence::<B, E, M>(
                        x, id, data, ext_memory, position, registry,
                    )?,
                    info: propagated.info,
                })
            }
        },
        SpecialtyTypeChecked::AccountId32 => Ok(ExtendedData {
            data: AccountId32::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Era => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                data: special_case_era::<B, E>(data, ext_memory, position)?,
                info: propagated.info,
            })
        }
        SpecialtyTypeChecked::H160 => Ok(ExtendedData {
            data: H160::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::H256 => {
            propagated.reject_compact()?;
            Ok(ExtendedData {
                data: special_case_h256::<B, E>(
                    data,
                    ext_memory,
                    position,
                    propagated.checker.specialty_set.hash256(),
                )?,
                info: propagated.info,
            })
        }
        SpecialtyTypeChecked::H512 => Ok(ExtendedData {
            data: H512::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PalletSpecific {
            pallet_name,
            pallet_info,
            pallet_variant: _,
            item_ty_id: _,
            variants,
            item,
        } => {
            propagated.reject_compact()?;
            let variant_data =
                decode_variant::<B, E, M>(&variants, data, ext_memory, position, registry)?;
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
            data: Perbill::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Percent => Ok(ExtendedData {
            data: Percent::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Permill => Ok(ExtendedData {
            data: Permill::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::Perquintill => Ok(ExtendedData {
            data: Perquintill::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PerU16 => Ok(ExtendedData {
            data: PerU16::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PublicEd25519 => Ok(ExtendedData {
            data: PublicEd25519::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PublicSr25519 => Ok(ExtendedData {
            data: PublicSr25519::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::PublicEcdsa => Ok(ExtendedData {
            data: PublicEcdsa::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::SignatureEd25519 => Ok(ExtendedData {
            data: SignatureEd25519::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::SignatureSr25519 => Ok(ExtendedData {
            data: SignatureSr25519::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
        SpecialtyTypeChecked::SignatureEcdsa => Ok(ExtendedData {
            data: SignatureEcdsa::parse_check_compact::<B, E>(
                data,
                ext_memory,
                position,
                propagated.compact_at(),
            )?,
            info: propagated.info,
        }),
    }
}

/// Parse part of data as a set of [`Field`]s. Used for structs, enums and
/// pallet-specific items.
///
/// Current parser position gets changed.
fn decode_fields<B, E, M>(
    fields: &[Field<PortableForm>],
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    mut checker: Checker,
) -> Result<Vec<FieldData>, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
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
        let field_name = field.name.to_owned();
        let type_name = field.type_name.to_owned();
        let this_field_data = decode_with_type::<B, E, M>(
            &Ty::Symbol(&field.ty),
            data,
            ext_memory,
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
fn decode_elements_set<B, E, M>(
    element: &UntrackedSymbol<TypeId>,
    number_of_elements: u32,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    propagated: Propagated,
) -> Result<ExtendedData, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    propagated.reject_compact()?;

    let husked = husk_type::<E, M>(element, registry, ext_memory, propagated.checker)?;

    let data = {
        if number_of_elements == 0 {
            ParsedData::SequenceRaw(SequenceRawData {
                element_info: husked.info,
                data: Vec::new(),
            })
        } else {
            let mut out: Vec<ParsedData> = Vec::new();
            for _i in 0..number_of_elements {
                let element_extended_data = decode_with_type::<B, E, M>(
                    &Ty::Resolved(ResolvedTy {
                        ty: husked.ty.to_owned(),
                        id: husked.id,
                    }),
                    data,
                    ext_memory,
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
/// Does not shift the current parser position.
pub fn pick_variant<'a, B, E>(
    variants: &'a [Variant<PortableForm>],
    data: &B,
    ext_memory: &mut E,
    position: usize,
) -> Result<&'a Variant<PortableForm>, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
{
    let enum_index = data.read_byte(ext_memory, position)?;

    let mut found_variant = None;
    for x in variants.iter() {
        if x.index == enum_index {
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
fn decode_variant<B, E, M>(
    variants: &[Variant<PortableForm>],
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
) -> Result<VariantData, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let found_variant = pick_variant::<B, E>(variants, data, ext_memory, *position)?;
    *position += ENUM_INDEX_ENCODED_LEN;
    let variant_name = found_variant.name.to_owned();
    let variant_docs = found_variant.collect_docs();
    let fields = decode_fields::<B, E, M>(
        &found_variant.fields,
        data,
        ext_memory,
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
#[derive(Debug)]
pub enum FoundBitOrder {
    Lsb0,
    Msb0,
}

/// Determine `BitOrder` type of [`TypeDefBitSequence`].
pub fn find_bit_order_ty<E, M>(
    bit_ty: &TypeDefBitSequence<PortableForm>,
    id: u32,
    ext_memory: &mut E,
    registry: &M::TypeRegistry,
) -> Result<FoundBitOrder, RegistryError<E>>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let bitorder_type = registry.resolve_ty(bit_ty.bit_order_type.id, ext_memory)?;
    match &bitorder_type.type_def {
        TypeDef::Composite(_) => match bitorder_type.path.ident() {
            Some(x) => match x.as_str() {
                LSB0 => Ok(FoundBitOrder::Lsb0),
                MSB0 => Ok(FoundBitOrder::Msb0),
                _ => Err(RegistryError::Internal(
                    RegistryInternalError::NotBitOrderType { id },
                )),
            },
            None => Err(RegistryError::Internal(
                RegistryInternalError::NotBitOrderType { id },
            )),
        },
        _ => Err(RegistryError::Internal(
            RegistryInternalError::NotBitOrderType { id },
        )),
    }
}

/// [`Type`]-associated [`Path`](scale_info::Path) `ident` for
/// [bitvec::order::Msb0].
const MSB0: &str = "Msb0";

/// [`Type`]-associated [`Path`](scale_info::Path) `ident` for
/// [bitvec::order::Lsb0].
const LSB0: &str = "Lsb0";

/// Parse part of data as a bitvec.
fn decode_type_def_bit_sequence<B, E, M>(
    bit_ty: &TypeDefBitSequence<PortableForm>,
    id: u32,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
) -> Result<ParsedData, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let bitvec_start = *position;

    // BitOrder
    let bitorder = find_bit_order_ty::<E, M>(bit_ty, id, ext_memory, registry)?;

    // BitStore
    let bitstore_type = registry.resolve_ty(bit_ty.bit_store_type.id, ext_memory)?;

    match bitstore_type.type_def {
        TypeDef::Primitive(TypeDefPrimitive::U8) => {
            let into_decode = into_bitvec_decode::<u8, B, E>(data, ext_memory, position)?;
            match bitorder {
                FoundBitOrder::Lsb0 => <BitVec<u8, Lsb0>>::decode_all(&mut into_decode.as_ref())
                    .map(ParsedData::BitVecU8Lsb0)
                    .map_err(|_| ParserError::TypeFailure {
                        position: bitvec_start,
                        ty: "BitVec<u8, Lsb0>",
                    }),
                FoundBitOrder::Msb0 => <BitVec<u8, Msb0>>::decode_all(&mut into_decode.as_ref())
                    .map(ParsedData::BitVecU8Msb0)
                    .map_err(|_| ParserError::TypeFailure {
                        position: bitvec_start,
                        ty: "BitVec<u8, Msb0>",
                    }),
            }
        }
        TypeDef::Primitive(TypeDefPrimitive::U16) => {
            let into_decode = into_bitvec_decode::<u16, B, E>(data, ext_memory, position)?;
            match bitorder {
                FoundBitOrder::Lsb0 => <BitVec<u16, Lsb0>>::decode_all(&mut into_decode.as_ref())
                    .map(ParsedData::BitVecU16Lsb0)
                    .map_err(|_| ParserError::TypeFailure {
                        position: bitvec_start,
                        ty: "BitVec<u16, Lsb0>",
                    }),
                FoundBitOrder::Msb0 => <BitVec<u16, Msb0>>::decode_all(&mut into_decode.as_ref())
                    .map(ParsedData::BitVecU16Msb0)
                    .map_err(|_| ParserError::TypeFailure {
                        position: bitvec_start,
                        ty: "BitVec<u16, Msb0>",
                    }),
            }
        }
        TypeDef::Primitive(TypeDefPrimitive::U32) => {
            let into_decode = into_bitvec_decode::<u32, B, E>(data, ext_memory, position)?;
            match bitorder {
                FoundBitOrder::Lsb0 => <BitVec<u32, Lsb0>>::decode_all(&mut into_decode.as_ref())
                    .map(ParsedData::BitVecU32Lsb0)
                    .map_err(|_| ParserError::TypeFailure {
                        position: bitvec_start,
                        ty: "BitVec<u32, Lsb0>",
                    }),
                FoundBitOrder::Msb0 => <BitVec<u32, Msb0>>::decode_all(&mut into_decode.as_ref())
                    .map(ParsedData::BitVecU32Msb0)
                    .map_err(|_| ParserError::TypeFailure {
                        position: bitvec_start,
                        ty: "BitVec<u32, Msb0>",
                    }),
            }
        }
        #[cfg(target_pointer_width = "64")]
        TypeDef::Primitive(TypeDefPrimitive::U64) => {
            let into_decode = into_bitvec_decode::<u64, B, E>(data, ext_memory, position)?;
            match bitorder {
                FoundBitOrder::Lsb0 => <BitVec<u64, Lsb0>>::decode_all(&mut into_decode.as_ref())
                    .map(ParsedData::BitVecU64Lsb0)
                    .map_err(|_| ParserError::TypeFailure {
                        position: bitvec_start,
                        ty: "BitVec<u64, Lsb0>",
                    }),
                FoundBitOrder::Msb0 => <BitVec<u64, Msb0>>::decode_all(&mut into_decode.as_ref())
                    .map(ParsedData::BitVecU64Msb0)
                    .map_err(|_| ParserError::TypeFailure {
                        position: bitvec_start,
                        ty: "BitVec<u64, Msb0>",
                    }),
            }
        }
        #[cfg(target_pointer_width = "32")]
        TypeDef::Primitive(TypeDefPrimitive::U64) => match bitorder {
            FoundBitOrder::Lsb0 => Lsb0::patch_bitvec_u64::<B, E>(data, ext_memory, position)
                .map(ParsedData::BitVecU64Lsb0),
            FoundBitOrder::Msb0 => Msb0::patch_bitvec_u64::<B, E>(data, ext_memory, position)
                .map(ParsedData::BitVecU64Msb0),
        },
        _ => Err(ParserError::Registry(RegistryError::Internal(
            RegistryInternalError::NotBitStoreType { id },
        ))),
    }
}

/// Positions and related values for decoding `BitVec`.
#[derive(Debug)]
pub struct BitVecPositions {
    /// Encoded `BitVec` start position, includes bit length compact.
    bitvec_start: usize,

    /// Data start position, after bit length compact, for patch only.
    #[cfg(any(target_pointer_width = "32", test))]
    data_start: usize,

    /// Encoded `BitVec` end position.
    pub bitvec_end: usize,

    /// Number of bits in `BitVec`, for patch only.
    #[cfg(any(target_pointer_width = "32", test))]
    bit_length: usize,

    /// Number of `BitStore`-sized elements in `BitVec`, for patch only.
    #[cfg(any(target_pointer_width = "32", test))]
    number_of_elements: usize,

    /// Minimal encoded data length.
    minimal_length: usize,
}

impl BitVecPositions {
    /// New `BitVecPositions` for given input data and position.
    ///
    /// `T` is corresponding `BitStore`.
    pub fn new<T, B, E>(
        data: &B,
        ext_memory: &mut E,
        position: usize,
    ) -> Result<Self, ParserError<E>>
    where
        B: AddressableBuffer<E>,
        E: ExternalMemory,
    {
        let found_compact = find_compact::<u32, B, E>(data, ext_memory, position)?;

        let bitvec_start = position;
        let data_start = found_compact.start_next_unit;

        let bit_length = found_compact.compact as usize;

        const BITS_IN_BYTE: usize = 8;
        let byte_length = match bit_length % BITS_IN_BYTE {
            0 => bit_length / BITS_IN_BYTE,
            _ => (bit_length / BITS_IN_BYTE) + 1usize,
        };

        let bytes_per_element = size_of::<T>();
        let number_of_elements = match byte_length % bytes_per_element {
            0 => byte_length / bytes_per_element,
            _ => (byte_length / bytes_per_element) + 1usize,
        };

        let slice_length = number_of_elements * bytes_per_element;

        let bitvec_end = data_start + slice_length;

        let minimal_length = bitvec_end - bitvec_start;

        Ok(Self {
            bitvec_start,
            #[cfg(any(target_pointer_width = "32", test))]
            data_start,
            bitvec_end,
            #[cfg(any(target_pointer_width = "32", test))]
            bit_length,
            #[cfg(any(target_pointer_width = "32", test))]
            number_of_elements,
            minimal_length,
        })
    }
}

/// Select the slice to decode as a `BitVec`.
///
/// Current parser position gets changed.
fn into_bitvec_decode<'a, T, B, E>(
    data: &B,
    ext_memory: &'a mut E,
    position: &'a mut usize,
) -> Result<B::ReadBuffer, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
{
    let bitvec_positions = BitVecPositions::new::<T, B, E>(data, ext_memory, *position)?;

    let into_bitvec_decode = data.read_slice(
        ext_memory,
        bitvec_positions.bitvec_start,
        bitvec_positions.minimal_length,
    )?;
    *position = bitvec_positions.bitvec_end;
    Ok(into_bitvec_decode)
}

/// Provide patch for `BitVec` with `u64` `BitStore` in 32bit targets.
#[cfg(any(target_pointer_width = "32", test))]
trait Patched: BitOrder + Sized {
    fn patch_bitvec_u64<B, E>(
        data: &B,
        ext_memory: &mut E,
        position: &mut usize,
    ) -> Result<BitVec<u32, Self>, ParserError<E>>
    where
        B: AddressableBuffer<E>,
        E: ExternalMemory;
}

/// Bytes in each individual element of `BitVec`, for u64.
#[cfg(any(target_pointer_width = "32", test))]
const BYTES_PER_ELEMENT_U64: usize = 8;

/// Bytes in each individual element of `BitVec`, for u32.
#[cfg(any(target_pointer_width = "32", test))]
const BYTES_PER_ELEMENT_U32: usize = 4;

/// Implement `Patched` for available `BitOrder` types.
#[cfg(any(target_pointer_width = "32", test))]
macro_rules! impl_patched {
    ($($bitorder: ty, $reform_vec_fn: ident), *) => {
        $(
            impl Patched for $bitorder {
                fn patch_bitvec_u64<B, E>(data: &B, ext_memory: &mut E, position: &mut usize) -> Result<BitVec<u32, Self>, ParserError<E>>
                where
                    B: AddressableBuffer<E>,
                    E: ExternalMemory
                {
                    let bitvec_positions = BitVecPositions::new::<u64, B, E>(data, ext_memory, *position)?;

                    let mut data_chunked: Vec<[u8; BYTES_PER_ELEMENT_U64]> = Vec::new();

                    for i in 0..bitvec_positions.number_of_elements {
                        match data.read_slice(
                            ext_memory, bitvec_positions.data_start + i * BYTES_PER_ELEMENT_U64, BYTES_PER_ELEMENT_U64,
                        ) {
                            Ok(data_part) => data_chunked.push(
                                data_part
                                    .as_ref()
                                    .try_into()
                                    .expect("constant size slice, always fits"),
                            ),
                            Err(_) => {
                                return Err(ParserError::Buffer(
                                BufferError::DataTooShort {
                                    position: bitvec_positions.bitvec_start,
                                    minimal_length: bitvec_positions.minimal_length,
                                }))
                            }
                        }
                    }

                    // collected all element chunks, safe to move the position to `BitVec` end,
                    // no more `position` moves made here
                    *position = bitvec_positions.bitvec_end;

                    let data_reformed = $reform_vec_fn(data_chunked);

                    let mut bv_reformed = BitVec::<u32, $bitorder>::from_vec(data_reformed);

                    bv_reformed.split_off(bitvec_positions.bit_length);

                    Ok(bv_reformed)
                }
            }
        )*
    }
}

/// Re-arrange SCALE-encoded data for 64bit `Lsb0` bitvecs.
#[cfg(any(target_pointer_width = "32", test))]
fn reform_vec_lsb0(data_chunked: Vec<[u8; BYTES_PER_ELEMENT_U64]>) -> Vec<u32> {
    let mut data_reformed: Vec<u32> = Vec::new();
    for (i, element) in data_chunked.iter().enumerate() {
        let new_element1 = u32::from_le_bytes(
            element[..BYTES_PER_ELEMENT_U32]
                .try_into()
                .expect("constant size slice, always fits"),
        );
        let new_element2 = u32::from_le_bytes(
            element[BYTES_PER_ELEMENT_U32..]
                .try_into()
                .expect("constant size slice, always fits"),
        );
        data_reformed.push(new_element1);
        if (new_element1 != 0) || (i != data_chunked.len() - 1) {
            data_reformed.push(new_element2)
        }
    }
    data_reformed
}

/// Re-arrange SCALE-encoded data for 64bit `Msb0` bitvecs.
#[cfg(any(target_pointer_width = "32", test))]
fn reform_vec_msb0(data_chunked: Vec<[u8; BYTES_PER_ELEMENT_U64]>) -> Vec<u32> {
    let mut data_reformed: Vec<u32> = Vec::new();
    for (i, x) in data_chunked.iter().enumerate() {
        let number = u64::from_le_bytes(*x);
        let element = number.to_be_bytes();
        let new_element1 = u32::from_be_bytes(
            element[..BYTES_PER_ELEMENT_U32]
                .try_into()
                .expect("constant size slice, always fits"),
        );
        let new_element2 = u32::from_be_bytes(
            element[BYTES_PER_ELEMENT_U32..]
                .try_into()
                .expect("constant size slice, always fits"),
        );
        if (new_element1 != 0) || (i != data_chunked.len() - 1) {
            data_reformed.push(new_element1)
        }
        data_reformed.push(new_element2);
    }
    data_reformed
}

#[cfg(any(target_pointer_width = "32", test))]
impl_patched!(Lsb0, reform_vec_lsb0);

#[cfg(any(target_pointer_width = "32", test))]
impl_patched!(Msb0, reform_vec_msb0);

/// Type of set element, resolved as completely as possible.
///
/// Elements in set (vector or array) could have complex solvable descriptions.
///
/// Element [`Info`] is collected while resolving the type. No identical
/// [`Type`] `id`s are expected to be encountered (these are collected and
/// checked in [`Checker`]), otherwise the resolving would go indefinitely.
#[derive(Debug)]
pub struct HuskedType {
    pub info: Vec<Info>,
    pub checker: Checker,
    pub ty: Type<PortableForm>,
    pub id: u32,
}

/// Resolve [`Type`] of set element.
///
/// Compact and single-field structs are resolved into corresponding inner
/// types. All available [`Info`] is collected.
pub fn husk_type<E, M>(
    entry_symbol: &UntrackedSymbol<TypeId>,
    registry: &M::TypeRegistry,
    ext_memory: &mut E,
    mut checker: Checker,
) -> Result<HuskedType, RegistryError<E>>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let entry_symbol_id = entry_symbol.id;
    checker.check_id(entry_symbol_id)?;
    checker.specialty_set = SpecialtySet {
        compact_at: None,
        hint: Hint::None,
    };

    let mut ty = registry.resolve_ty(entry_symbol_id, ext_memory)?;
    let mut id = entry_symbol_id;
    let mut info: Vec<Info> = Vec::new();

    loop {
        let info_ty = Info::from_ty(&ty);
        if !info_ty.is_empty() {
            info.push(info_ty)
        }

        if let SpecialtyTypeHinted::None = SpecialtyTypeHinted::from_type(&ty) {
            let type_def = ty.type_def.to_owned();
            match type_def {
                TypeDef::Composite(x) => {
                    if x.fields.len() == 1 {
                        id = x.fields[0].ty.id;
                        checker.check_id(id)?;
                        ty = registry.resolve_ty(id, ext_memory)?;
                        if let Hint::None = checker.specialty_set.hint {
                            checker.specialty_set.hint = Hint::from_field(&x.fields[0])
                        }
                    } else {
                        break;
                    }
                }
                TypeDef::Compact(x) => {
                    checker.reject_compact()?;
                    checker.specialty_set.compact_at = Some(id);
                    id = x.type_param.id;
                    checker.check_id(id)?;
                    ty = registry.resolve_ty(id, ext_memory)?;
                }
                _ => break,
            }
        } else {
            break;
        }
    }

    Ok(HuskedType {
        info,
        checker,
        ty,
        id,
    })
}

/// Type information used for parsing.
#[derive(Debug)]
pub enum Ty<'a> {
    /// Type is already resolved in metadata types registry.
    Resolved(ResolvedTy),

    /// Type is not yet resolved.
    Symbol(&'a UntrackedSymbol<TypeId>),
}

///Type previously resolved in metadata types registry.
#[derive(Debug)]
pub struct ResolvedTy {
    pub ty: Type<PortableForm>,
    pub id: u32,
}

#[cfg(target_pointer_width = "64")]
#[cfg(test)]
mod tests {
    use bitvec::bitvec;
    use parity_scale_codec::Encode;

    use super::*;
    use crate::std::string::ToString;

    #[test]
    fn bitvec_correct_cut_1() {
        let bv = BitVec::<u8, Lsb0>::from_vec(vec![3, 14, 15]);
        let encoded_data = [bv.encode(), [0; 30].to_vec()].concat();
        let mut position = 0;
        let into_decode =
            into_bitvec_decode::<u8, &[u8], ()>(&encoded_data.as_ref(), &mut (), &mut position)
                .unwrap();
        assert_eq!(bv.encode(), into_decode);
    }

    #[test]
    fn bitvec_correct_cut_2() {
        let bv = BitVec::<u64, Msb0>::from_vec(vec![128, 1234567890123456, 0, 4234567890123456]);
        let encoded_data = [bv.encode(), [0; 30].to_vec()].concat();
        let mut position = 0;
        let into_decode =
            into_bitvec_decode::<u64, &[u8], ()>(&encoded_data.as_ref(), &mut (), &mut position)
                .unwrap();
        assert_eq!(bv.encode(), into_decode);
    }

    #[test]
    fn bitvec_patch_1() {
        let bv1 = BitVec::<u64, Lsb0>::from_vec(vec![128, 1234567890123456, 0, 4234567890123456]);
        let bv1_encoded = bv1.encode();

        let mut position = 0usize;
        let bv2 = Lsb0::patch_bitvec_u64(&bv1_encoded.as_ref(), &mut (), &mut position).unwrap();
        assert_eq!(position, bv1_encoded.len());
        assert_eq!(bv1.to_string(), bv2.to_string());
    }

    #[test]
    fn bitvec_patch_2() {
        let mut bv1 = bitvec![u64, Lsb0; 1; 60];
        let bv1_ext = bitvec![u64, Lsb0; 0; 30];
        bv1.extend_from_bitslice(&bv1_ext);
        let bv1_encoded = bv1.encode();

        let mut position = 0usize;
        let bv2 = Lsb0::patch_bitvec_u64(&bv1_encoded.as_ref(), &mut (), &mut position).unwrap();
        assert_eq!(position, bv1_encoded.len());
        assert_eq!(bv1.to_string(), bv2.to_string());
    }

    #[test]
    fn bitvec_patch_3() {
        let bv1 = BitVec::<u64, Msb0>::from_vec(vec![128, 1234567890123456, 0, 4234567890123456]);
        let bv1_encoded = bv1.encode();

        let mut position = 0usize;
        let bv2 = Msb0::patch_bitvec_u64(&bv1_encoded.as_ref(), &mut (), &mut position).unwrap();
        assert_eq!(position, bv1_encoded.len());
        assert_eq!(bv1.to_string(), bv2.to_string());
    }

    #[test]
    fn bitvec_patch_4() {
        let mut bv1 = bitvec![u64, Msb0; 1; 60];
        let bv1_ext = bitvec![u64, Msb0; 0; 30];
        bv1.extend_from_bitslice(&bv1_ext);
        let bv1_encoded = bv1.encode();

        let mut position = 0usize;
        let bv2 = Msb0::patch_bitvec_u64(&bv1_encoded.as_ref(), &mut (), &mut position).unwrap();
        assert_eq!(position, bv1_encoded.len());
        assert_eq!(bv1.to_string(), bv2.to_string());
    }
}
