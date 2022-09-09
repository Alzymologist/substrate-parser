//! Decode signable transaction extensions using `RuntimeMetadataV14`.
use sp_core::H256;
use sp_runtime::generic::Era;

use crate::cards::{ExtendedData, ParsedData};
use crate::decoding_sci::{decode_with_type, Ty};
use crate::error::{ExtensionsError, SignableError};
use crate::metadata_check::CheckedMetadata;
use crate::propagated::Propagated;
use crate::special_indicators::SpecialtyPrimitive;
use crate::special_types::StLenCheckSpecialtyCompact;

pub fn decode_ext_attempt(
    data: &mut Vec<u8>,
    checked_metadata: &CheckedMetadata,
    genesis_hash: H256,
) -> Result<Vec<ExtendedData>, SignableError> {
    let mut extensions: Vec<ExtendedData> = Vec::new();
    for signed_extensions_metadata in checked_metadata.meta_v14.extrinsic.signed_extensions.iter() {
        extensions.push(
            decode_with_type(
                &Ty::Symbol(&signed_extensions_metadata.ty),
                data,
                checked_metadata.meta_v14,
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
                checked_metadata.meta_v14,
                Propagated::from_ext_meta(signed_extensions_metadata),
            )
            .map_err(SignableError::Parsing)?,
        )
    }
    if !data.is_empty() {
        return Err(SignableError::SomeDataNotUsedExtensions);
    }
    check_extensions(&extensions, &checked_metadata.version, genesis_hash)?;
    Ok(extensions)
}

pub fn check_extensions(
    extensions: &[ExtendedData],
    version: &str,
    genesis_hash: H256,
) -> Result<(), SignableError> {
    let mut collected_ext = CollectedExt::new();
    for ext in extensions.iter() {
        match ext.data {
            ParsedData::Era(era) => collected_ext.add_era(era)?,
            ParsedData::GenesisHash(h) => collected_ext.add_genesis_hash(h)?,
            ParsedData::BlockHash(h) => collected_ext.add_block_hash(h)?,
            ParsedData::PrimitiveU8 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => collected_ext.add_spec_version::<u8>(value)?,
            ParsedData::PrimitiveU16 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => collected_ext.add_spec_version::<u16>(value)?,
            ParsedData::PrimitiveU32 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => collected_ext.add_spec_version::<u32>(value)?,
            ParsedData::PrimitiveU64 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => collected_ext.add_spec_version::<u64>(value)?,
            ParsedData::PrimitiveU128 {
                value,
                specialty: SpecialtyPrimitive::SpecVersion,
            } => collected_ext.add_spec_version::<u128>(value)?,
            ParsedData::Composite(ref field_data) => {
                if field_data.len() == 1 {
                    match field_data[0].data.data {
                        ParsedData::Era(era) => collected_ext.add_era(era)?,
                        ParsedData::GenesisHash(h) => collected_ext.add_genesis_hash(h)?,
                        ParsedData::BlockHash(h) => collected_ext.add_block_hash(h)?,
                        ParsedData::PrimitiveU8 {
                            value,
                            specialty: SpecialtyPrimitive::SpecVersion,
                        } => collected_ext.add_spec_version::<u8>(value)?,
                        ParsedData::PrimitiveU16 {
                            value,
                            specialty: SpecialtyPrimitive::SpecVersion,
                        } => collected_ext.add_spec_version::<u16>(value)?,
                        ParsedData::PrimitiveU32 {
                            value,
                            specialty: SpecialtyPrimitive::SpecVersion,
                        } => collected_ext.add_spec_version::<u32>(value)?,
                        ParsedData::PrimitiveU64 {
                            value,
                            specialty: SpecialtyPrimitive::SpecVersion,
                        } => collected_ext.add_spec_version::<u64>(value)?,
                        ParsedData::PrimitiveU128 {
                            value,
                            specialty: SpecialtyPrimitive::SpecVersion,
                        } => collected_ext.add_spec_version::<u128>(value)?,
                        _ => (),
                    }
                }
            }
            _ => (),
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

struct CollectedExt {
    era: Option<Era>,
    genesis_hash: Option<H256>,
    block_hash: Option<H256>,
    spec_version_printed: Option<String>,
}

impl CollectedExt {
    fn new() -> Self {
        Self {
            era: None,
            genesis_hash: None,
            block_hash: None,
            spec_version_printed: None,
        }
    }
    fn add_era(&mut self, era: Era) -> Result<(), SignableError> {
        if self.era.is_some() {
            Err(SignableError::ExtensionsList(ExtensionsError::EraTwice))
        } else {
            self.era = Some(era);
            Ok(())
        }
    }
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
    fn add_spec_version<T: StLenCheckSpecialtyCompact>(
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
