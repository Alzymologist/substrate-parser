#[cfg(not(feature = "std"))]
use core::{
    any::TypeId,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};
#[cfg(feature = "std")]
use std::{
    any::TypeId,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

use crate::std::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

use frame_metadata::v14::{ExtrinsicMetadata, PalletMetadata, RuntimeMetadataV14};
use parity_scale_codec::{Decode, Encode};
use scale_info::{form::PortableForm, interner::UntrackedSymbol, PortableRegistry, Type};

use crate::cards::ParsedData;
use crate::decode_all_as_type;
use crate::error::{MetaVersionErrorPallets, ParserError};
use crate::special_indicators::{SpecialtyStr, SpecialtyUnsignedInteger};

pub trait ExternalMemory: Debug {
    type ExternalMemoryError: Debug + Display + Eq + PartialEq;
}

impl ExternalMemory for () {
    type ExternalMemoryError = NoEntries;
}

#[derive(Debug, Eq, PartialEq)]
pub enum NoEntries {}

impl Display for NoEntries {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "")
    }
}

pub trait AddressableBuffer<E: ExternalMemory> {
    type ReadBuffer: AsRef<[u8]>;
    fn total_len(&self) -> usize;
    fn read_slice(
        &self,
        ext_memory: &mut E,
        position: usize,
        slice_len: usize,
    ) -> Result<Self::ReadBuffer, ParserError<E>>;
    fn read_byte(&self, ext_memory: &mut E, position: usize) -> Result<u8, ParserError<E>> {
        let byte_slice = self.read_slice(ext_memory, position, 1)?;
        Ok(byte_slice.as_ref()[0])
    }
    /// Limits the available buffer length to shorter `new_len` provided.
    ///
    /// If `new_len` exceeds initial `total_len`, panics. This should be
    /// used only with pre-checked `new_len`.
    ///
    /// Mostly for call decoding, so that the input stops when the call ends.
    fn limit_length(&self, new_len: usize) -> Self;
}

impl<'a, E: ExternalMemory> AddressableBuffer<E> for &'a [u8] {
    type ReadBuffer = &'a [u8];
    fn total_len(&self) -> usize {
        self.len()
    }
    fn read_slice(
        &self,
        _ext_memory: &mut E,
        position: usize,
        slice_len: usize,
    ) -> Result<Self::ReadBuffer, ParserError<E>> {
        if self.len() < position {
            return Err(ParserError::OutOfRange {
                position,
                total_length: self.len(),
            });
        }
        match self.get(position..position + slice_len) {
            Some(a) => Ok(a),
            None => Err(ParserError::DataTooShort {
                position,
                minimal_length: slice_len,
            }),
        }
    }
    fn limit_length(&self, new_len: usize) -> Self {
        &self[..new_len]
    }
}

pub trait AsMetadata<E: ExternalMemory>: Debug + Sized {
    type TypeRegistry: ResolveType<E>;
    type MetaStructureError: Debug + Display + Eq;
    fn types(&self) -> Self::TypeRegistry;
    fn spec_name_version(&self) -> Result<SpecNameVersion, Self::MetaStructureError>;
    fn extrinsic(&self) -> Result<ExtrinsicMetadata<PortableForm>, Self::MetaStructureError>;
}

#[repr(C)]
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct SpecNameVersion {
    pub printed_spec_version: String,
    pub spec_name: String,
}

pub trait ResolveType<E: ExternalMemory> {
    fn resolve_ty(&self, id: u32, ext_memory: &mut E)
        -> Result<Type<PortableForm>, ParserError<E>>;
}

impl<E: ExternalMemory> ResolveType<E> for PortableRegistry {
    fn resolve_ty(
        &self,
        id: u32,
        _ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, ParserError<E>> {
        match self.resolve(id) {
            Some(a) => Ok(a.to_owned()),
            None => Err(ParserError::V14TypeNotResolved { id }),
        }
    }
}

impl<E: ExternalMemory> AsMetadata<E> for RuntimeMetadataV14 {
    type TypeRegistry = PortableRegistry;

    type MetaStructureError = MetaVersionErrorPallets;

    fn types(&self) -> Self::TypeRegistry {
        self.types.to_owned()
    }

    fn spec_name_version(&self) -> Result<SpecNameVersion, Self::MetaStructureError> {
        let (value, ty) = runtime_version_data_and_ty(&self.pallets)?;
        match decode_all_as_type::<&[u8], (), RuntimeMetadataV14>(
            &ty,
            &value.as_ref(),
            &mut (),
            &self.types,
        ) {
            Ok(extended_data) => spec_name_version_from_runtime_version_data(extended_data.data),
            Err(_) => Err(MetaVersionErrorPallets::RuntimeVersionNotDecodeable),
        }
    }

    fn extrinsic(&self) -> Result<ExtrinsicMetadata<PortableForm>, Self::MetaStructureError> {
        Ok(self.extrinsic.to_owned())
    }
}

fn runtime_version_data_and_ty(
    pallets: &[PalletMetadata<PortableForm>],
) -> Result<(Vec<u8>, UntrackedSymbol<TypeId>), MetaVersionErrorPallets> {
    let mut runtime_version_data_and_ty = None;
    let mut system_block = false;
    for pallet in pallets.iter() {
        if pallet.name == "System" {
            system_block = true;
            for constant in pallet.constants.iter() {
                if constant.name == "Version" {
                    runtime_version_data_and_ty = Some((constant.value.to_vec(), constant.ty))
                }
            }
            break;
        }
    }
    if !system_block {
        return Err(MetaVersionErrorPallets::NoSystemPallet);
    }
    runtime_version_data_and_ty.ok_or(MetaVersionErrorPallets::NoVersionInConstants)
}

fn spec_name_version_from_runtime_version_data(
    parsed_data: ParsedData,
) -> Result<SpecNameVersion, MetaVersionErrorPallets> {
    let mut printed_spec_version = None;
    let mut spec_name = None;

    if let ParsedData::Composite(fields) = parsed_data {
        for field in fields.iter() {
            match &field.data.data {
                ParsedData::PrimitiveU8 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::PrimitiveU16 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::PrimitiveU32 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::PrimitiveU64 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::PrimitiveU128 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::Text {
                    text,
                    specialty: SpecialtyStr::SpecName,
                } => {
                    if spec_name.is_none() {
                        spec_name = Some(text.to_owned())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecNameIdentifierTwice);
                    }
                }
                _ => (),
            }
        }
    } else {
        return Err(MetaVersionErrorPallets::UnexpectedRuntimeVersionFormat);
    }
    let printed_spec_version = match printed_spec_version {
        Some(a) => a,
        None => return Err(MetaVersionErrorPallets::NoSpecVersionIdentifier),
    };
    let spec_name = match spec_name {
        Some(a) => a,
        None => return Err(MetaVersionErrorPallets::NoSpecNameIdentifier),
    };
    Ok(SpecNameVersion {
        printed_spec_version,
        spec_name,
    })
}
