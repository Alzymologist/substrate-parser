//! Decode unchecked extrinsics, signed or unsigned.
//!
//! Unchecked extrinsics are assumed to be SCALE-encoded opaque `Vec<u8>`, its
//! general structure described
//! [here](https://docs.substrate.io/reference/transaction-format/). It could be
//! signed or unsigned, the type
//! [`UncheckedExtrinsic`](https://docs.rs/sp-runtime/latest/sp_runtime/generic/struct.UncheckedExtrinsic.html)
//! itself contains metadata-specific blocks, the types of which could be found
//! in metadata.
//!
//! Signed unchecked extrinsic structure:
//!
//! <table>
//!   <tr>
//!     <td>compact length of whole extrinsic</td>
//!     <td>version byte</td>
//!     <td>address that produced the extrinsic</td>
//!     <td>signature</td>
//!     <td>extra data</td>
//!     <td>call</td>
//!   </tr>
//! </table>
//!
//! Unsigned unchecked extrinsic structure:
//!
//! <table>
//!   <tr>
//!     <td>compact length of whole extrinsic</td>
//!     <td>version byte</td>
//!     <td>call</td>
//!   </tr>
//! </table>
//!
//! Signed and unsigned unchecked extrinsics are differentiated by version byte.
//! The first bit in the version byte is `0` if the extrinsic is unsigned and
//! `1` if the extrinsic is signed. Other 7 bits must match the extrinsic
//! `version`, found, for example, in `version` field of
//! [`v14::ExtrinsicMetadata`](https://docs.rs/frame-metadata/latest/frame_metadata/v14/struct.ExtrinsicMetadata.html)
//! or [`v15::ExtrinsicMetadata`](https://docs.rs/frame-metadata/latest/frame_metadata/v15/struct.ExtrinsicMetadata.html).
//! Currently the `version` has a constant value of `4` (see
//! [`EXTRINSIC_FORMAT_VERSION`](https://docs.rs/sp-runtime/31.0.1/src/sp_runtime/generic/unchecked_extrinsic.rs.html#39)
//! in `sp_runtime`, thus version byte is `0x04` for unsigned extrinsics and
//! `0x84` for signed extrinsics.
//!
//! Types defining unchecked extrinsic content, i.e. `call_ty`, `address_ty`,
//! `extra_ty`, `signature_ty`, and `version` value are determined for metadata
//! implementing [`AsCompleteMetadata`] trait.
#[cfg(feature = "std")]
use std::cmp::Ordering;

#[cfg(not(feature = "std"))]
use core::cmp::Ordering;

use external_memory_tools::{AddressableBuffer, BufferError, ExternalMemory};

use crate::cards::{Call, ExtendedData, ParsedData};
use crate::compacts::get_compact;
use crate::decode_as_type_at_position;
use crate::error::{ParserError, UncheckedExtrinsicError};
use crate::traits::AsCompleteMetadata;

/// Length of version indicator, 1 byte.
const VERSION_LENGTH: usize = 1;

/// Version byte mask, to separate version and signed/unsigned information.
const VERSION_MASK: u8 = 0b0111_1111;

/// Version value for unsigned extrinsic, after `VERSION_MASK` is applied.
const VERSION_UNSIGNED: u8 = 0;

/// Decode an unchecked extrinsic.
pub fn decode_as_unchecked_extrinsic<B, E, M>(
    input: &B,
    ext_memory: &mut E,
    metadata: &M,
) -> Result<UncheckedExtrinsic, UncheckedExtrinsicError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsCompleteMetadata<E>,
{
    let extrinsic_type_params = metadata
        .extrinsic_type_params()
        .map_err(UncheckedExtrinsicError::MetaStructure)?;
    let registry = metadata.types();

    // This could have been just a single decode line.
    // Written this way to: (1) trace position from the start, (2) have descriptive errors
    let mut extrinsic_start: usize = 0;
    let extrinsic_length = get_compact::<u32, B, E>(input, ext_memory, &mut extrinsic_start)
        .map_err(|_| UncheckedExtrinsicError::FormatNoCompact)? as usize;
    let len = input.total_len();
    match (extrinsic_start + extrinsic_length).cmp(&len) {
        Ordering::Greater => {
            return Err(UncheckedExtrinsicError::Parsing(ParserError::Buffer(
                BufferError::DataTooShort {
                    position: len,
                    minimal_length: extrinsic_start + extrinsic_length - len,
                },
            )))
        }
        Ordering::Less => {
            return Err(UncheckedExtrinsicError::Parsing(
                ParserError::SomeDataNotUsedBlob {
                    from: extrinsic_start + extrinsic_length,
                },
            ))
        }
        Ordering::Equal => {}
    }

    let mut position = extrinsic_start;

    // version byte from extrinsic, to diffirentiate signed and unsigned extrinsics
    let version_byte = input
        .read_byte(ext_memory, position)
        .map_err(|e| UncheckedExtrinsicError::Parsing(ParserError::Buffer(e)))?;
    position += VERSION_LENGTH;

    let version = metadata
        .extrinsic_version()
        .map_err(UncheckedExtrinsicError::MetaStructure)?;

    // First bit of `version_byte` is `0` if the transaction is unsigned and `1` if the transaction is signed.
    // Other 7 bits must match the `version` from the metadata.
    if version_byte & VERSION_MASK != version {
        Err(UncheckedExtrinsicError::VersionMismatch {
            version_byte,
            version,
        })
    } else if version_byte & !VERSION_MASK == VERSION_UNSIGNED {
        let call_extended_data = decode_as_type_at_position::<B, E, M>(
            &extrinsic_type_params.call_ty,
            input,
            ext_memory,
            &registry,
            &mut position,
        )?;
        if let ParsedData::Call(call) = call_extended_data.data {
            Ok(UncheckedExtrinsic::Unsigned { call })
        } else {
            Err(UncheckedExtrinsicError::UnexpectedCallTy {
                call_ty_id: extrinsic_type_params.call_ty.id,
            })
        }
    } else {
        let address = decode_as_type_at_position::<B, E, M>(
            &extrinsic_type_params.address_ty,
            input,
            ext_memory,
            &registry,
            &mut position,
        )?;

        let signature = decode_as_type_at_position::<B, E, M>(
            &extrinsic_type_params.signature_ty,
            input,
            ext_memory,
            &registry,
            &mut position,
        )?;

        let extra = decode_as_type_at_position::<B, E, M>(
            &extrinsic_type_params.extra_ty,
            input,
            ext_memory,
            &registry,
            &mut position,
        )?;

        let call_extended_data = decode_as_type_at_position::<B, E, M>(
            &extrinsic_type_params.call_ty,
            input,
            ext_memory,
            &registry,
            &mut position,
        )?;
        if let ParsedData::Call(call) = call_extended_data.data {
            Ok(UncheckedExtrinsic::Signed {
                address,
                signature,
                extra,
                call,
            })
        } else {
            Err(UncheckedExtrinsicError::UnexpectedCallTy {
                call_ty_id: extrinsic_type_params.call_ty.id,
            })
        }
    }
}

/// Decoded unchecked extrinsic.
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
