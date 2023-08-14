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
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use frame_metadata::v14::{ExtrinsicMetadata, PalletMetadata, RuntimeMetadataV14};
use parity_scale_codec::{Decode, Encode};
use scale_info::{form::PortableForm, interner::UntrackedSymbol, PortableRegistry, Type};

use crate::cards::ParsedData;
use crate::cut_metadata::{DraftMetadataHeader, ShortMetadata, ShortRegistry};
use crate::decode_all_as_type;
use crate::decoding_sci::ResolvedTy;
use crate::error::{MetaVersionError, ParserError, SignableError};
use crate::special_indicators::SpecialtyPrimitive;

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

pub trait AsMetadata<E: ExternalMemory> {
    type TypeRegistry: ResolveType<E>;
    type PalletMetadataEntry: AsPallet<E>;
    fn types(&self) -> Self::TypeRegistry;
    fn pallet_by_index(&self, index: u8) -> Result<Self::PalletMetadataEntry, SignableError<E>>;
    fn call_ty(
        pallet: &Self::PalletMetadataEntry,
        types: &Self::TypeRegistry,
        ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, SignableError<E>>;
    fn version_printed(&self) -> Result<String, MetaVersionError>;
    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm>;
}

pub trait ResolveType<E: ExternalMemory> {
    fn resolve_ty(&self, id: u32, ext_memory: &mut E)
        -> Result<Type<PortableForm>, ParserError<E>>;
    fn resolve_ty_external_id(
        &self,
        external_id: u32,
        ext_memory: &mut E,
    ) -> Result<ResolvedTy, ParserError<E>>;
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
    fn resolve_ty_external_id(
        &self,
        external_id: u32,
        ext_memory: &mut E,
    ) -> Result<ResolvedTy, ParserError<E>> {
        let ty = self.resolve_ty(external_id, ext_memory)?;
        Ok(ResolvedTy {
            ty,
            id: external_id,
        })
    }
}

pub trait AsPallet<E: ExternalMemory> {
    fn name(&self) -> String;
    fn index(&self) -> u8;
    fn call_ty_id(&self) -> Result<u32, SignableError<E>>;
}

impl<E: ExternalMemory> AsPallet<E> for PalletMetadata<PortableForm> {
    fn name(&self) -> String {
        self.name.to_owned()
    }
    fn index(&self) -> u8 {
        self.index
    }
    fn call_ty_id(&self) -> Result<u32, SignableError<E>> {
        match self.calls.as_ref() {
            Some(pallet_call_metadata) => Ok(pallet_call_metadata.ty.id),
            None => Err(SignableError::NoCallsInPallet(
                <PalletMetadata<PortableForm> as AsPallet<E>>::name(self),
            )),
        }
    }
}

impl<E: ExternalMemory> AsMetadata<E> for RuntimeMetadataV14 {
    type TypeRegistry = PortableRegistry;

    type PalletMetadataEntry = PalletMetadata<PortableForm>;

    fn types(&self) -> Self::TypeRegistry {
        self.types.to_owned()
    }

    fn pallet_by_index(&self, index: u8) -> Result<Self::PalletMetadataEntry, SignableError<E>> {
        for x in self.pallets.iter() {
            if x.index == index {
                return Ok(x.to_owned());
            }
        }
        Err(SignableError::PalletNotFound(index))
    }

    fn call_ty(
        pallet: &Self::PalletMetadataEntry,
        types: &Self::TypeRegistry,
        ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, SignableError<E>> {
        let call_ty_id = pallet.call_ty_id()?;

        types
            .resolve_ty(call_ty_id, ext_memory)
            .map_err(SignableError::Parsing)
    }

    fn version_printed(&self) -> Result<String, MetaVersionError> {
        let (value, ty) = runtime_version_data_and_ty(&self.pallets)?;
        match decode_all_as_type::<&[u8], (), RuntimeMetadataV14>(
            &ty,
            &value.as_ref(),
            &mut (),
            &self.types,
        ) {
            Ok(extended_data) => find_version_in_parsed_data(extended_data.data),
            Err(_) => Err(MetaVersionError::RuntimeVersionNotDecodeable),
        }
    }

    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm> {
        self.extrinsic.to_owned()
    }
}

pub struct PortableRegistryShortened {
    pub registry: PortableRegistry,
    pub map: BTreeMap<u32, u32>,
}

impl<E: ExternalMemory> ResolveType<E> for PortableRegistryShortened {
    fn resolve_ty(
        &self,
        id: u32,
        _ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, ParserError<E>> {
        match self.registry.resolve(id) {
            Some(a) => Ok(a.to_owned()),
            None => Err(ParserError::V14TypeNotResolved { id }),
        }
    }
    fn resolve_ty_external_id(
        &self,
        external_id: u32,
        ext_memory: &mut E,
    ) -> Result<ResolvedTy, ParserError<E>> {
        if let Some(internal_id) = self.map.get(&external_id) {
            let ty = self.registry.resolve_ty(*internal_id, ext_memory)?;
            Ok(ResolvedTy {
                ty,
                id: *internal_id,
            })
        } else {
            Err(ParserError::V14ShortTypesIncomplete {
                old_id: external_id,
            })
        }
    }
}

#[derive(Debug, Decode, Encode)]
pub struct RuntimeMetadataV14Shortened {
    pub meta_v14: RuntimeMetadataV14,
    pub map: BTreeMap<u32, u32>,
}

impl<E: ExternalMemory> AsMetadata<E> for RuntimeMetadataV14Shortened {
    type TypeRegistry = PortableRegistryShortened;

    type PalletMetadataEntry = PalletMetadata<PortableForm>;

    fn types(&self) -> Self::TypeRegistry {
        PortableRegistryShortened {
            registry: self.meta_v14.types.to_owned(),
            map: self.map.to_owned(),
        }
    }

    fn pallet_by_index(&self, index: u8) -> Result<Self::PalletMetadataEntry, SignableError<E>> {
        for x in self.meta_v14.pallets.iter() {
            if x.index == index {
                return Ok(x.clone());
            }
        }
        Err(SignableError::PalletNotFound(index))
    }

    fn call_ty(
        pallet: &Self::PalletMetadataEntry,
        types: &Self::TypeRegistry,
        ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, SignableError<E>> {
        let call_ty_id = pallet.call_ty_id()?;
        if let Some(call_ty_id_new) = types.map.get(&call_ty_id) {
            types
                .resolve_ty(*call_ty_id_new, ext_memory)
                .map_err(SignableError::Parsing)
        } else {
            Err(SignableError::Parsing(
                ParserError::V14ShortTypesIncomplete { old_id: call_ty_id },
            ))
        }
    }

    fn version_printed(&self) -> Result<String, MetaVersionError> {
        let (value, ty) = runtime_version_data_and_ty(&self.meta_v14.pallets)?;
        match decode_all_as_type::<&[u8], (), RuntimeMetadataV14Shortened>(
            &ty,
            &value.as_ref(),
            &mut (),
            &<RuntimeMetadataV14Shortened as AsMetadata<E>>::types(self),
        ) {
            Ok(extended_data) => find_version_in_parsed_data(extended_data.data),
            Err(_) => Err(MetaVersionError::RuntimeVersionNotDecodeable),
        }
    }

    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm> {
        self.meta_v14.extrinsic.to_owned()
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

    type PalletMetadataEntry = PalletMetadata<PortableForm>;

    fn types(&self) -> Self::TypeRegistry {
        self.meta_v14.types.to_owned()
    }

    fn pallet_by_index(&self, index: u8) -> Result<Self::PalletMetadataEntry, SignableError<E>> {
        for x in self.meta_v14.pallets.iter() {
            if x.index == index {
                return Ok(x.to_owned());
            }
        }
        Err(SignableError::PalletNotFound(index))
    }

    fn call_ty(
        pallet: &Self::PalletMetadataEntry,
        types: &Self::TypeRegistry,
        ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, SignableError<E>> {
        RuntimeMetadataV14::call_ty(pallet, types, ext_memory)
    }

    fn version_printed(&self) -> Result<String, MetaVersionError> {
        Ok(self.version.to_owned())
    }

    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm> {
        self.meta_v14.extrinsic.to_owned()
    }
}

fn runtime_version_data_and_ty(
    pallets: &[PalletMetadata<PortableForm>],
) -> Result<(Vec<u8>, UntrackedSymbol<TypeId>), MetaVersionError> {
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
        return Err(MetaVersionError::NoSystemPallet);
    }
    runtime_version_data_and_ty.ok_or(MetaVersionError::NoVersionInConstants)
}

fn find_version_in_parsed_data(parsed_data: ParsedData) -> Result<String, MetaVersionError> {
    let mut spec_version = None;
    if let ParsedData::Composite(fields) = parsed_data {
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
    match spec_version {
        Some(a) => Ok(a),
        None => Err(MetaVersionError::NoSpecVersionIdentifier),
    }
}

impl<E: ExternalMemory> ResolveType<E> for ShortRegistry {
    fn resolve_ty(
        &self,
        id: u32,
        _ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, ParserError<E>> {
        for short_registry_entry in self.types.iter() {
            if short_registry_entry.id == id {
                return Ok(short_registry_entry.ty.to_owned());
            }
        }
        Err(ParserError::V14TypeNotResolved { id })
    }
    fn resolve_ty_external_id(
        &self,
        external_id: u32,
        ext_memory: &mut E,
    ) -> Result<ResolvedTy, ParserError<E>> {
        let ty = self.resolve_ty(external_id, ext_memory)?;
        Ok(ResolvedTy {
            ty,
            id: external_id,
        })
    }
}

impl<E: ExternalMemory> AsPallet<E> for DraftMetadataHeader {
    fn name(&self) -> String {
        self.pallet_name.to_owned()
    }
    fn index(&self) -> u8 {
        self.index
    }
    fn call_ty_id(&self) -> Result<u32, SignableError<E>> {
        Ok(self.call_ty_id)
    }
}

impl<E: ExternalMemory> AsMetadata<E> for ShortMetadata {
    type TypeRegistry = ShortRegistry;

    type PalletMetadataEntry = DraftMetadataHeader;

    fn types(&self) -> Self::TypeRegistry {
        self.short_registry.to_owned()
    }

    fn pallet_by_index(&self, index: u8) -> Result<Self::PalletMetadataEntry, SignableError<E>> {
        if self.pallet_index == index {
            Ok(DraftMetadataHeader {
                pallet_name: self.pallet_name.to_owned(),
                call_ty_id: self.pallet_call_ty_id,
                index: self.pallet_index,
            })
        } else {
            Err(SignableError::PalletNotFound(index))
        }
    }

    fn call_ty(
        pallet: &Self::PalletMetadataEntry,
        types: &Self::TypeRegistry,
        ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, SignableError<E>> {
        let call_ty_id = pallet.call_ty_id()?;

        types
            .resolve_ty(call_ty_id, ext_memory)
            .map_err(SignableError::Parsing)
    }

    fn version_printed(&self) -> Result<String, MetaVersionError> {
        Ok(String::from("9111"))
    }

    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm> {
        self.extrinsic.to_owned()
    }
}
