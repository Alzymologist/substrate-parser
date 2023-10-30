//! Decode signable transaction extensions using `RuntimeMetadataV14`.
use primitive_types::H256;

#[cfg(not(feature = "std"))]
use crate::additional_types::Era;
#[cfg(feature = "std")]
use sp_runtime::generic::Era;

use crate::std::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

use crate::cards::{ExtendedData, ParsedData};
use crate::decoding_sci::{decode_with_type, Ty};
use crate::error::{ExtensionsError, SignableError};
use crate::propagated::Propagated;
use crate::special_indicators::SpecialtyUnsignedInteger;
use crate::special_types::UnsignedInteger;
use crate::traits::{AddressableBuffer, AsMetadata, ExternalMemory};
use crate::MarkedData;

/// Parse extensions part of the signable transaction [`MarkedData`] using
/// provided `V14` metadata.
///
/// Extensions data is expected to be decoded completely, with no data left.
///
/// Metadata spec version and chain genesis hash are used to check that correct
/// metadata is used for parsing.
///
/// Extensions and their order are determined by `signed_extensions` in
/// [`ExtrinsicMetadata`](frame_metadata::v14::ExtrinsicMetadata).
///
/// Whole `signed_extensions` set is scanned first for types in `ty` field, and
/// then the second time, for types in `additional_signed` field.
pub fn decode_extensions<B, E, M>(
    marked_data: &MarkedData<B, E>,
    ext_memory: &mut E,
    meta_v14: &M,
    optional_genesis_hash: Option<H256>,
) -> Result<Vec<ExtendedData>, SignableError<E>>
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
        meta_v14,
        optional_genesis_hash,
    )
}

/// Parse extensions part of the signable transaction using provided metadata.
///
/// Extensions data is expected to be decoded completely, with no data left.
///
/// Metadata spec version and chain genesis hash are used to check that correct
/// metadata is used for parsing.
///
/// Extensions and their order are determined by `signed_extensions` in
/// [`ExtrinsicMetadata`](frame_metadata::v14::ExtrinsicMetadata).
///
/// Whole `signed_extensions` set is scanned first for types in `ty` field, and
/// then the second time, for types in `additional_signed` field.
pub fn decode_extensions_unmarked<B, E, M>(
    data: &B,
    position: &mut usize,
    ext_memory: &mut E,
    meta_v14: &M,
    optional_genesis_hash: Option<H256>,
) -> Result<Vec<ExtendedData>, SignableError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut extensions: Vec<ExtendedData> = Vec::new();
    let meta_v14_types = meta_v14.types();
    for signed_extensions_metadata in meta_v14.extrinsic().signed_extensions.iter() {
        extensions.push(
            decode_with_type::<B, E, M>(
                &Ty::Symbol(&signed_extensions_metadata.ty),
                data,
                ext_memory,
                position,
                &meta_v14_types,
                Propagated::from_ext_meta(signed_extensions_metadata),
            )
            .map_err(SignableError::Parsing)?,
        )
    }
    for signed_extensions_metadata in meta_v14.extrinsic().signed_extensions.iter() {
        extensions.push(
            decode_with_type::<B, E, M>(
                &Ty::Symbol(&signed_extensions_metadata.additional_signed),
                data,
                ext_memory,
                position,
                &meta_v14_types,
                Propagated::from_ext_meta(signed_extensions_metadata),
            )
            .map_err(SignableError::Parsing)?,
        )
    }
    // `position > data.total_len()` is ruled out elsewhere
    if *position != data.total_len() {
        return Err(SignableError::SomeDataNotUsedExtensions { from: *position });
    }
    let spec_name_version = meta_v14
        .spec_name_version()
        .map_err(SignableError::MetaVersion)?;
    check_extensions::<E>(
        &extensions,
        &spec_name_version.printed_spec_version,
        optional_genesis_hash,
    )?;
    Ok(extensions)
}

/// Check collected extensions.
///
/// Extensions must include metadata spec version and chain genesis hash.
/// If extensions also include `Era`, block hash for immortal `Era` must match
/// chain genesis hash.
fn check_extensions<E: ExternalMemory>(
    extensions: &[ExtendedData],
    version: &str,
    optional_genesis_hash: Option<H256>,
) -> Result<(), SignableError<E>> {
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
    fn update<E: ExternalMemory>(
        &mut self,
        parsed_data: &ParsedData,
    ) -> Result<(), SignableError<E>> {
        match parsed_data {
            ParsedData::Era(era) => self.add_era::<E>(*era),
            ParsedData::GenesisHash(h) => self.add_genesis_hash::<E>(*h),
            ParsedData::BlockHash(h) => self.add_block_hash::<E>(*h),
            ParsedData::PrimitiveU8 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u8, E>(*value),
            ParsedData::PrimitiveU16 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u16, E>(*value),
            ParsedData::PrimitiveU32 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u32, E>(*value),
            ParsedData::PrimitiveU64 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u64, E>(*value),
            ParsedData::PrimitiveU128 {
                value,
                specialty: SpecialtyUnsignedInteger::SpecVersion,
            } => self.add_spec_version::<u128, E>(*value),
            _ => Ok(()),
        }
    }

    /// Add `Era` to set.
    fn add_era<E: ExternalMemory>(&mut self, era: Era) -> Result<(), SignableError<E>> {
        if self.era.is_some() {
            Err(SignableError::ExtensionsList(ExtensionsError::EraTwice))
        } else {
            self.era = Some(era);
            Ok(())
        }
    }

    /// Add genesis hash to set.
    fn add_genesis_hash<E: ExternalMemory>(
        &mut self,
        genesis_hash: H256,
    ) -> Result<(), SignableError<E>> {
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
    fn add_block_hash<E: ExternalMemory>(
        &mut self,
        block_hash: H256,
    ) -> Result<(), SignableError<E>> {
        if self.block_hash.is_some() {
            Err(SignableError::ExtensionsList(
                ExtensionsError::BlockHashTwice,
            ))
        } else {
            self.block_hash = Some(block_hash);
            Ok(())
        }
    }

    /// Add metadata spec version to set.
    fn add_spec_version<T: UnsignedInteger, E: ExternalMemory>(
        &mut self,
        spec_version: T,
    ) -> Result<(), SignableError<E>> {
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
