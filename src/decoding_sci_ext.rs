//! Decode signable transaction extensions using metadata with in-built type
//! descriptors.
use external_memory_tools::{AddressableBuffer, ExternalMemory};
use primitive_types::H256;

use crate::std::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

use crate::additional_types::Era;
use crate::cards::{ExtendedData, ParsedData};
use crate::decoding_sci::{decode_with_type, Ty};
use crate::error::{ExtensionsError, SignableError};
use crate::propagated::Propagated;
use crate::special_indicators::SpecialtyUnsignedInteger;
use crate::special_types::UnsignedInteger;
use crate::traits::AsMetadata;
use crate::MarkedData;

/// Parse extensions part of the signable transaction [`MarkedData`] using
/// provided metadata.
///
/// Extensions data is expected to be decoded completely, with no data left.
///
/// Metadata `spec_version` and chain genesis hash (if provided) are used to
/// check that correct metadata is used for parsing. All extensions are
/// displayed as parsed for user for final checking.
///
/// Extensions and their order are determined by `signed_extensions`, a set of
/// [`SignedExtensionMetadata`](crate::traits::SignedExtensionMetadata) known
/// for each type implementing `AsMetadata`.
///
/// Whole `signed_extensions` set is scanned first for types in `ty` field, and
/// then the second time, for types in `additional_signed` field.
pub fn decode_extensions<B, E, M>(
    marked_data: &MarkedData<B, E, M>,
    ext_memory: &mut E,
    metadata: &M,
    optional_genesis_hash: Option<H256>,
) -> Result<Vec<ExtendedData>, SignableError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut position = marked_data.extensions_start();
    let data = marked_data.data();

    decode_extensions_unmarked(
        data,
        &mut position,
        ext_memory,
        metadata,
        optional_genesis_hash,
    )
}

/// Parse extensions part of the signable transaction using provided metadata.
///
/// Extensions data is expected to be decoded completely, with no data left.
///
/// Metadata `spec_version` and chain genesis hash (if provided) are used to
/// check that correct metadata is used for parsing. All extensions are
/// displayed as parsed for user for final checking.
///
/// Extensions and their order are determined by `signed_extensions`, a set of
/// [`SignedExtensionMetadata`](crate::traits::SignedExtensionMetadata) known
/// for each type implementing `AsMetadata`.
///
/// Whole `signed_extensions` set is scanned first for types in `ty` field, and
/// then the second time, for types in `additional_signed` field.
pub fn decode_extensions_unmarked<B, E, M>(
    data: &B,
    position: &mut usize,
    ext_memory: &mut E,
    metadata: &M,
    optional_genesis_hash: Option<H256>,
) -> Result<Vec<ExtendedData>, SignableError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut extensions: Vec<ExtendedData> = Vec::new();
    let registry = metadata.types();
    let signed_extensions = metadata
        .signed_extensions()
        .map_err(SignableError::MetaStructure)?;
    for signed_extensions_metadata in signed_extensions.iter() {
        extensions.push(decode_with_type::<B, E, M>(
            &Ty::Symbol(&signed_extensions_metadata.ty),
            data,
            ext_memory,
            position,
            &registry,
            Propagated::from_ext_meta(signed_extensions_metadata),
        )?)
    }
    for signed_extensions_metadata in signed_extensions.iter() {
        extensions.push(decode_with_type::<B, E, M>(
            &Ty::Symbol(&signed_extensions_metadata.additional_signed),
            data,
            ext_memory,
            position,
            &registry,
            Propagated::from_ext_meta(signed_extensions_metadata),
        )?)
    }
    // `position > data.total_len()` is ruled out elsewhere
    if *position != data.total_len() {
        return Err(SignableError::SomeDataNotUsedExtensions { from: *position });
    }
    let spec_name_version = metadata
        .spec_name_version()
        .map_err(SignableError::MetaStructure)?;
    check_extensions::<E, M>(
        &extensions,
        &spec_name_version.printed_spec_version,
        optional_genesis_hash,
    )?;
    Ok(extensions)
}

/// Check collected extensions.
///
/// Extensions must include metadata `spec_version` and chain genesis hash.
/// If extensions also include `Era`, block hash for immortal `Era` must match
/// chain genesis hash.
fn check_extensions<E: ExternalMemory, M: AsMetadata<E>>(
    extensions: &[ExtendedData],
    version: &str,
    optional_genesis_hash: Option<H256>,
) -> Result<(), SignableError<E, M>> {
    let mut collected_ext = CollectedExt::new();
    for ext in extensions.iter() {
        // single-field structs are also checked
        if let ParsedData::Composite(ref field_data) = ext.data {
            if field_data.len() == 1 {
                collected_ext.update(&field_data[0].data.data)?;
            }
        } else {
            collected_ext.update(&ext.data)?;
        }
    }
    match collected_ext.spec_version_printed {
        Some(spec_version_found) => {
            if spec_version_found != version {
                return Err(SignableError::WrongSpecVersion {
                    as_decoded: spec_version_found,
                    in_metadata: version.to_owned(),
                });
            }
        }
        None => {
            return Err(SignableError::ExtensionsList(
                ExtensionsError::NoSpecVersion,
            ))
        }
    }
    match collected_ext.genesis_hash {
        Some(found_genesis_hash) => {
            if let Some(genesis_hash) = optional_genesis_hash {
                if found_genesis_hash != genesis_hash {
                    return Err(SignableError::WrongGenesisHash {
                        as_decoded: found_genesis_hash,
                        expected: genesis_hash,
                    });
                }
            }
        }
        None => {
            return Err(SignableError::ExtensionsList(
                ExtensionsError::NoGenesisHash,
            ))
        }
    }
    if let Some(Era::Immortal) = collected_ext.era {
        if let Some(block_hash) = collected_ext.block_hash {
            if let Some(genesis_hash) = collected_ext.genesis_hash {
                if genesis_hash != block_hash {
                    return Err(SignableError::ImmortalHashMismatch);
                }
            }
        }
    }
    Ok(())
}

/// Collector for extensions that must be checked.
struct CollectedExt {
    era: Option<Era>,
    genesis_hash: Option<H256>,
    block_hash: Option<H256>,
    spec_version_printed: Option<String>,
}

impl CollectedExt {
    /// Initiate new set.
    fn new() -> Self {
        Self {
            era: None,
            genesis_hash: None,
            block_hash: None,
            spec_version_printed: None,
        }
    }

    /// Update set with `ParsedData`.
    fn update<E: ExternalMemory, M: AsMetadata<E>>(
        &mut self,
        parsed_data: &ParsedData,
    ) -> Result<(), SignableError<E, M>> {
        match parsed_data {
            ParsedData::Era(era) => self.add_era::<E, M>(*era),
            ParsedData::GenesisHash(h) => self.add_genesis_hash::<E, M>(*h),
            ParsedData::BlockHash(h) => self.add_block_hash::<E, M>(*h),
            ParsedData::PrimitiveU8 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u8, E, M>(*value),
            ParsedData::PrimitiveU16 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u16, E, M>(*value),
            ParsedData::PrimitiveU32 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u32, E, M>(*value),
            ParsedData::PrimitiveU64 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u64, E, M>(*value),
            ParsedData::PrimitiveU128 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u128, E, M>(*value),
            _ => Ok(()),
        }
    }

    /// Add `Era` to set.
    fn add_era<E: ExternalMemory, M: AsMetadata<E>>(
        &mut self,
        era: Era,
    ) -> Result<(), SignableError<E, M>> {
        if self.era.is_some() {
            Err(SignableError::ExtensionsList(ExtensionsError::EraTwice))
        } else {
            self.era = Some(era);
            Ok(())
        }
    }

    /// Add genesis hash to set.
    fn add_genesis_hash<E: ExternalMemory, M: AsMetadata<E>>(
        &mut self,
        genesis_hash: H256,
    ) -> Result<(), SignableError<E, M>> {
        if self.genesis_hash.is_some() {
            Err(SignableError::ExtensionsList(
                ExtensionsError::GenesisHashTwice,
            ))
        } else {
            self.genesis_hash = Some(genesis_hash);
            Ok(())
        }
    }

    /// Add block hash to set.
    fn add_block_hash<E: ExternalMemory, M: AsMetadata<E>>(
        &mut self,
        block_hash: H256,
    ) -> Result<(), SignableError<E, M>> {
        if self.block_hash.is_some() {
            Err(SignableError::ExtensionsList(
                ExtensionsError::BlockHashTwice,
            ))
        } else {
            self.block_hash = Some(block_hash);
            Ok(())
        }
    }

    /// Add metadata `spec_version` to set.
    fn add_spec_version<T: UnsignedInteger, E: ExternalMemory, M: AsMetadata<E>>(
        &mut self,
        spec_version: T,
    ) -> Result<(), SignableError<E, M>> {
        if self.spec_version_printed.is_some() {
            Err(SignableError::ExtensionsList(
                ExtensionsError::SpecVersionTwice,
            ))
        } else {
            self.spec_version_printed = Some(spec_version.to_string());
            Ok(())
        }
    }
}
