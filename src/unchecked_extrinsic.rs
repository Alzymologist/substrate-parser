//! It is assumed here that the unchecked extrinsic is encoded as opaque
//! `Vec<u8>`.
#[cfg(feature = "std")]
use std::cmp::Ordering;

#[cfg(not(feature = "std"))]
use core::cmp::Ordering;

use frame_metadata::v14::RuntimeMetadataV14;
use scale_info::{TypeDef, TypeDefPrimitive};

use crate::cards::{Call, ExtendedData, ParsedData};
use crate::compacts::get_compact;
use crate::decode_as_type_at_position;
use crate::decoding_sci::resolve_ty;
use crate::error::{ParserError, UncheckedExtrinsicError};

const VERSION_LENGTH: usize = 1;
const VERSION_MASK: u8 = 0b0111_1111;
const VERSION_UNSIGNED: u8 = 0;

const ADDRESS_INDICATOR: &str = "Address";
const SIGNATURE_INDICATOR: &str = "Signature";
const EXTRA_INDICATOR: &str = "Extra";
const CALL_INDICATOR: &str = "Call";

pub fn decode_as_unchecked_extrinsic(
    input: &[u8],
    meta_v14: &RuntimeMetadataV14,
) -> Result<UncheckedExtrinsic, UncheckedExtrinsicError> {
    let extrinsic_ty_id = meta_v14.extrinsic.ty.id();
    let extrinsic_ty =
        resolve_ty(&meta_v14.types, extrinsic_ty_id).map_err(UncheckedExtrinsicError::Parser)?;

    // check here that the underlying type is really `Vec<u8>`
    match extrinsic_ty.type_def() {
        TypeDef::Sequence(s) => {
            let element_ty_id = s.type_param().id();
            let element_ty = resolve_ty(&meta_v14.types, element_ty_id)
                .map_err(UncheckedExtrinsicError::Parser)?;
            if let TypeDef::Primitive(TypeDefPrimitive::U8) = element_ty.type_def() {
            } else {
                return Err(UncheckedExtrinsicError::UnexpectedType { extrinsic_ty_id });
            }
        }
        TypeDef::Composite(c) => {
            let fields = c.fields();
            if fields.len() != 1 {
                return Err(UncheckedExtrinsicError::UnexpectedType { extrinsic_ty_id });
            } else {
                let field_ty_id = fields[0].ty().id();
                let field_ty = resolve_ty(&meta_v14.types, field_ty_id)
                    .map_err(UncheckedExtrinsicError::Parser)?;
                match field_ty.type_def() {
                    TypeDef::Sequence(s) => {
                        let element_ty_id = s.type_param().id();
                        let element_ty = resolve_ty(&meta_v14.types, element_ty_id)
                            .map_err(UncheckedExtrinsicError::Parser)?;
                        if let TypeDef::Primitive(TypeDefPrimitive::U8) = element_ty.type_def() {
                        } else {
                            return Err(UncheckedExtrinsicError::UnexpectedType {
                                extrinsic_ty_id,
                            });
                        }
                    }
                    _ => return Err(UncheckedExtrinsicError::UnexpectedType { extrinsic_ty_id }),
                }
            }
        }
        _ => return Err(UncheckedExtrinsicError::UnexpectedType { extrinsic_ty_id }),
    }

    // This could have been just a single decode line.
    // Written this way to: (1) trace position from the start, (2) have descriptive errors
    let mut extrinsic_start: usize = 0;
    let extrinsic_length = get_compact::<u32>(input, &mut extrinsic_start)
        .map_err(|_| UncheckedExtrinsicError::FormatNoCompact)? as usize;
    let len = input.len();
    match (extrinsic_start + extrinsic_length).cmp(&len) {
        Ordering::Greater => {
            return Err(UncheckedExtrinsicError::Parser(ParserError::DataTooShort {
                position: len,
                minimal_length: extrinsic_start + extrinsic_length - len,
            }))
        }
        Ordering::Less => {
            return Err(UncheckedExtrinsicError::Parser(
                ParserError::SomeDataNotUsedBlob {
                    from: extrinsic_start + extrinsic_length,
                },
            ))
        }
        Ordering::Equal => {}
    }

    let mut position = extrinsic_start;

    // version byte from extrinsic, to diffirentiate signed and unsigned extrinsics
    let version_byte = match input.get(position) {
        Some(a) => {
            position += VERSION_LENGTH;
            *a
        }
        None => {
            return Err(UncheckedExtrinsicError::Parser(ParserError::DataTooShort {
                position,
                minimal_length: VERSION_LENGTH,
            }))
        }
    };

    // Currently the version is `4`, a constant defined in
    // <https://docs.rs/sp-runtime/latest/src/sp_runtime/generic/unchecked_extrinsic.rs.html#39>
    let version = meta_v14.extrinsic.version;

    // First bit of `version_byte` is `0` if the transaction is unsigned and `1` if the transaction is signed.
    // Other 7 bits must match the `version` from the metadata.
    if version_byte & VERSION_MASK != version {
        Err(UncheckedExtrinsicError::VersionMismatch {
            version_byte,
            version,
        })
    } else if version_byte & !VERSION_MASK == VERSION_UNSIGNED {
        let mut found_call = None;

        // Unchecked extrinsic parameters typically contain address, signature,
        // and extensions. Expect to find all entries.
        for param in extrinsic_ty.type_params() {
            if param.name() == CALL_INDICATOR {
                found_call = param.ty()
            }
        }

        let call_ty = found_call.ok_or(UncheckedExtrinsicError::NoCallParam)?;
        let call_extended_data =
            decode_as_type_at_position(call_ty, input, &meta_v14.types, &mut position)
                .map_err(UncheckedExtrinsicError::Parser)?;
        if let ParsedData::Call(call) = call_extended_data.data {
            Ok(UncheckedExtrinsic::Unsigned { call })
        } else {
            Err(UncheckedExtrinsicError::UnexpectedCallTy {
                call_ty_id: call_ty.id(),
            })
        }
    } else {
        let mut found_address = None;
        let mut found_signature = None;
        let mut found_extra = None;
        let mut found_call = None;

        // Unchecked extrinsic parameters typically contain address, signature,
        // and extensions. Expect to find all entries.
        for param in extrinsic_ty.type_params() {
            match param.name().as_str() {
                ADDRESS_INDICATOR => found_address = param.ty(),
                SIGNATURE_INDICATOR => found_signature = param.ty(),
                EXTRA_INDICATOR => found_extra = param.ty(),
                CALL_INDICATOR => found_call = param.ty(),
                _ => (),
            }
        }

        let address_ty = found_address.ok_or(UncheckedExtrinsicError::NoAddressParam)?;
        let address = decode_as_type_at_position(address_ty, input, &meta_v14.types, &mut position)
            .map_err(UncheckedExtrinsicError::Parser)?;

        let signature_ty = found_signature.ok_or(UncheckedExtrinsicError::NoSignatureParam)?;
        let signature =
            decode_as_type_at_position(signature_ty, input, &meta_v14.types, &mut position)
                .map_err(UncheckedExtrinsicError::Parser)?;

        let extra_ty = found_extra.ok_or(UncheckedExtrinsicError::NoExtraParam)?;
        let extra = decode_as_type_at_position(extra_ty, input, &meta_v14.types, &mut position)
            .map_err(UncheckedExtrinsicError::Parser)?;

        let call_ty = found_call.ok_or(UncheckedExtrinsicError::NoCallParam)?;
        let call_extended_data =
            decode_as_type_at_position(call_ty, input, &meta_v14.types, &mut position)
                .map_err(UncheckedExtrinsicError::Parser)?;
        if let ParsedData::Call(call) = call_extended_data.data {
            Ok(UncheckedExtrinsic::Signed {
                address,
                signature,
                extra,
                call,
            })
        } else {
            Err(UncheckedExtrinsicError::UnexpectedCallTy {
                call_ty_id: call_ty.id(),
            })
        }
    }
}

/// Unchecked extrinsic.
///
/// Could be signed or unsigned, see <https://docs.substrate.io/reference/transaction-format/>
/// for general format reference.
#[derive(Debug, Eq, PartialEq)]
pub enum UncheckedExtrinsic {
    Signed {
        address: ExtendedData,
        signature: ExtendedData,
        extra: ExtendedData,
        call: Call,
    },
    Unsigned {
        call: Call,
    },
}
