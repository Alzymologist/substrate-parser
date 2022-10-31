//! Decode signable transaction extensions using `RuntimeMetadataV14`.
use sp_core::H256;
use sp_runtime::generic::Era;

use crate::cards::{ExtendedData, ParsedData};
use crate::decoding_sci::{decode_with_type, Ty};
use crate::error::{ExtensionsError, SignableError};
use crate::metadata_check::CheckedMetadata;
use crate::propagated::Propagated;
use crate::special_indicators::SpecialtyPrimitive;
use crate::special_types::UnsignedInteger;

/// Parse signable transaction extensions with provided `V14` metadata.
///
/// Data gets consumed. All input data is expected to be used in parsing.
///
/// Metadata spec version and chain genesis hash are used to check that correct
/// metadata is used for parsing.
///
/// Extensions and their order are determined by `signed_extensions` in
/// [`ExtrinsicMetadata`](frame_metadata::v14::ExtrinsicMetadata).
///
/// Whole `signed_extensions` set is scanned first for types in `ty` field, and
/// then the second time, for types in `additional_signed` field.
pub fn decode_extensions(
    data: &[u8],
    mut position: usize,
    checked_metadata: &CheckedMetadata,
    genesis_hash: H256,
) -> Result<Vec<ExtendedData>, SignableError> {
    let mut extensions: Vec<ExtendedData> = Vec::new();
    for signed_extensions_metadata in checked_metadata.meta_v14.extrinsic.signed_extensions.iter() {
        extensions.push(
            decode_with_type(
                &Ty::Symbol(&signed_extensions_metadata.ty),
                data,
                &mut position,
                &checked_metadata.meta_v14.types,
                Propagated::from_ext_meta(signed_extensions_metadata),
            )
            .map_err(SignableError::Parsing)?,
        )
    }
    for signed_extensions_metadata in checked_metadata.meta_v14.extrinsic.signed_extensions.iter() {
        extensions.push(
            decode_with_type(
                &Ty::Symbol(&signed_extensions_metadata.additional_signed),
                data,
                &mut position,
                &checked_metadata.meta_v14.types,
                Propagated::from_ext_meta(signed_extensions_metadata),
            )
            .map_err(SignableError::Parsing)?,
        )
    }
    if position != data.len() {
        return Err(SignableError::SomeDataNotUsedExtensions { from: position });
    }
    check_extensions(&extensions, &checked_metadata.version, genesis_hash)?;
    Ok(extensions)
}

/// Check collected extensions.
///
/// Extensions must include metadata spec version and chain genesis hash.
/// If extensions also include `Era`, block hash for immortal `Era` must match
/// chain genesis hash.
fn check_extensions(
    extensions: &[ExtendedData],
    version: &str,
    genesis_hash: H256,
) -> Result<(), SignableError> {
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
            if found_genesis_hash != genesis_hash {
                return Err(SignableError::WrongGenesisHash {
                    as_decoded: found_genesis_hash,
                    expected: genesis_hash,
                });
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
            if genesis_hash != block_hash {
                return Err(SignableError::ImmortalHashMismatch);
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
    fn update(&mut self, parsed_data: &ParsedData) -> Result<(), SignableError> {
        match parsed_data {
            ParsedData::Era(era) => self.add_era(*era),
            ParsedData::GenesisHash(h) => self.add_genesis_hash(*h),
            ParsedData::BlockHash(h) => self.add_block_hash(*h),
            ParsedData::PrimitiveU8 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => self.add_spec_version::<u8>(*value),
            ParsedData::PrimitiveU16 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => self.add_spec_version::<u16>(*value),
            ParsedData::PrimitiveU32 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => self.add_spec_version::<u32>(*value),
            ParsedData::PrimitiveU64 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => self.add_spec_version::<u64>(*value),
            ParsedData::PrimitiveU128 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => self.add_spec_version::<u128>(*value),
            _ => Ok(()),
        }
    }

    /// Add `Era` to set.
    fn add_era(&mut self, era: Era) -> Result<(), SignableError> {
        if self.era.is_some() {
            Err(SignableError::ExtensionsList(ExtensionsError::EraTwice))
        } else {
            self.era = Some(era);
            Ok(())
        }
    }

    /// Add genesis hash to set.
    fn add_genesis_hash(&mut self, genesis_hash: H256) -> Result<(), SignableError> {
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
    fn add_block_hash(&mut self, block_hash: H256) -> Result<(), SignableError> {
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
    fn add_spec_version<T: UnsignedInteger>(
        &mut self,
        spec_version: T,
    ) -> Result<(), SignableError> {
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
