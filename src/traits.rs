#[cfg(not(feature = "std"))]
use core::any::TypeId;
#[cfg(feature = "std")]
use std::any::TypeId;

use crate::std::{
    borrow::ToOwned,
    string::{String, ToString},
};

use frame_metadata::v14::{ExtrinsicMetadata, RuntimeMetadataV14};
use scale_info::{form::PortableForm, interner::UntrackedSymbol, PortableRegistry, Type};

use crate::cards::ParsedData;
use crate::decode_all_as_type;
use crate::error::{MetaVersionError, ParserError, SignableError};
use crate::special_indicators::SpecialtyPrimitive;

pub trait ExternalMemory {}

impl ExternalMemory for () {}

pub trait AddressableBuffer<E: ExternalMemory> {
    type ReadBuffer: AsRef<[u8]>;
    fn total_len(&self) -> usize;
    fn read_slice(
        &self,
        ext_memory: &mut E,
        position: usize,
        slice_len: usize,
    ) -> Result<Self::ReadBuffer, ParserError>;
    fn read_byte(&self, ext_memory: &mut E, position: usize) -> Result<u8, ParserError> {
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
    ) -> Result<Self::ReadBuffer, ParserError> {
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

pub struct PalletCallTy {
    pub pallet_name: String,
    pub call_ty: Type<PortableForm>,
}

pub trait AsMetadata<E: ExternalMemory> {
    type TypeRegistry: ResolveType<E>;
    fn types(&self) -> &Self::TypeRegistry;
    fn find_calls_ty(
        &self,
        pallet_index: u8,
        ext_memory: &mut E,
    ) -> Result<PalletCallTy, SignableError>;
    fn version_printed(&self, ext_memory: &mut E) -> Result<String, MetaVersionError>;
    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm>;
    fn ty(&self) -> UntrackedSymbol<TypeId>;
}

pub trait ResolveType<E: ExternalMemory> {
    fn resolve_ty(&self, id: u32, ext_memory: &mut E) -> Result<Type<PortableForm>, ParserError>;
}

impl<E: ExternalMemory> ResolveType<E> for PortableRegistry {
    fn resolve_ty(&self, id: u32, _ext_memory: &mut E) -> Result<Type<PortableForm>, ParserError> {
        match self.resolve(id) {
            Some(a) => Ok(a.to_owned()),
            None => Err(ParserError::V14TypeNotResolved { id }),
        }
    }
}

impl<E: ExternalMemory> AsMetadata<E> for RuntimeMetadataV14 {
    type TypeRegistry = PortableRegistry;

    fn types(&self) -> &Self::TypeRegistry {
        &self.types
    }

    fn find_calls_ty(
        &self,
        pallet_index: u8,
        ext_memory: &mut E,
    ) -> Result<PalletCallTy, SignableError> {
        let mut found_calls_in_pallet: Option<UntrackedSymbol<TypeId>> = None;

        let mut found_pallet_name: Option<String> = None;
        for x in self.pallets.iter() {
            if x.index == pallet_index {
                found_pallet_name = Some(x.name.to_owned());
                if let Some(a) = &x.calls {
                    found_calls_in_pallet = Some(a.ty);
                }
                break;
            }
        }

        let pallet_name = match found_pallet_name {
            Some(a) => a,
            None => return Err(SignableError::PalletNotFound(pallet_index)),
        };

        let call_ty = match found_calls_in_pallet {
            Some(calls_in_pallet_symbol) => self
                .types
                .resolve_ty(calls_in_pallet_symbol.id(), ext_memory)
                .map_err(SignableError::Parsing)?,
            None => return Err(SignableError::NoCallsInPallet(pallet_name)),
        };

        Ok(PalletCallTy {
            pallet_name,
            call_ty,
        })
    }

    fn version_printed(&self, ext_memory: &mut E) -> Result<String, MetaVersionError> {
        let mut runtime_version_data_and_ty = None;
        let mut system_block = false;
        for pallet in self.pallets.iter() {
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
            return Err(MetaVersionError::NoSystemPallet);
        }
        let mut spec_version = None;
        match runtime_version_data_and_ty {
            Some((value, ty)) => {
                match decode_all_as_type::<&[u8], E, RuntimeMetadataV14>(
                    &ty,
                    &value.as_ref(),
                    ext_memory,
                    &self.types,
                ) {
                    Ok(extended_data) => {
                        if let ParsedData::Composite(fields) = extended_data.data {
                            for field in fields.iter() {
                                match field.data.data {
                                    ParsedData::PrimitiveU8 {
                                        value,
                                        specialty: SpecialtyPrimitive::SpecVersion,
                                    } => {
                                        spec_version = Some(value.to_string());
                                        break;
                                    }
                                    ParsedData::PrimitiveU16 {
                                        value,
                                        specialty: SpecialtyPrimitive::SpecVersion,
                                    } => {
                                        spec_version = Some(value.to_string());
                                        break;
                                    }
                                    ParsedData::PrimitiveU32 {
                                        value,
                                        specialty: SpecialtyPrimitive::SpecVersion,
                                    } => {
                                        spec_version = Some(value.to_string());
                                        break;
                                    }
                                    ParsedData::PrimitiveU64 {
                                        value,
                                        specialty: SpecialtyPrimitive::SpecVersion,
                                    } => {
                                        spec_version = Some(value.to_string());
                                        break;
                                    }
                                    ParsedData::PrimitiveU128 {
                                        value,
                                        specialty: SpecialtyPrimitive::SpecVersion,
                                    } => {
                                        spec_version = Some(value.to_string());
                                        break;
                                    }
                                    _ => (),
                                }
                            }
                        } else {
                            return Err(MetaVersionError::UnexpectedRuntimeVersionFormat);
                        }
                    }
                    Err(_) => return Err(MetaVersionError::RuntimeVersionNotDecodeable),
                }
            }
            None => return Err(MetaVersionError::NoVersionInConstants),
        }
        match spec_version {
            Some(a) => Ok(a),
            None => Err(MetaVersionError::NoSpecVersionIdentifier),
        }
    }

    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm> {
        self.extrinsic.to_owned()
    }

    fn ty(&self) -> UntrackedSymbol<TypeId> {
        self.ty
    }
}

/// Metadata with spec version.
pub struct CheckedMetadata {
    /// Runtime metadata.
    pub meta_v14: RuntimeMetadataV14,

    /// Metadata spec version, printed.
    pub version: String,
}

impl<E: ExternalMemory> AsMetadata<E> for CheckedMetadata {
    type TypeRegistry = PortableRegistry;

    fn types(&self) -> &Self::TypeRegistry {
        &self.meta_v14.types
    }

    fn find_calls_ty(
        &self,
        pallet_index: u8,
        ext_memory: &mut E,
    ) -> Result<PalletCallTy, SignableError> {
        self.meta_v14.find_calls_ty(pallet_index, ext_memory)
    }

    fn version_printed(&self, _ext_memory: &mut E) -> Result<String, MetaVersionError> {
        Ok(self.version.to_owned())
    }

    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm> {
        self.meta_v14.extrinsic.to_owned()
    }

    fn ty(&self) -> UntrackedSymbol<TypeId> {
        self.meta_v14.ty
    }
}
