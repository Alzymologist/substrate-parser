//! Determine metadata spec version.
//!
//! Metadata spec version is used when decoding signable transactions, to verify
//! that the metadata used for decoding has the same version as the metadata
//! used to generate the transaction. The metadata spec version used to
//! generate the transaction is one of the extensions.
//!
//! Metadata could be supplied into parser as `Raw` (metadata only) or as
//! `Checked` (metadata and spec version derived from elsewhere).
//! [`CheckedMetadata`] does not get re-checked in this crate.
use frame_metadata::v14::RuntimeMetadataV14;

use crate::cards::ParsedData;
use crate::decode_all_as_type;
use crate::error::MetaVersionError;
use crate::special_indicators::SpecialtyPrimitive;

/// Metadata with spec version.
pub struct CheckedMetadata<'a> {
    /// Runtime metadata.
    pub meta_v14: &'a RuntimeMetadataV14,

    /// Metadata spec version, printed.
    pub version: String,
}

/// Metadata used for signable transaction parsing.
pub enum MetaInput<'a> {
    /// Metadata is accompanied by spec version already determined elsewhere.
    ///
    /// No need to check the spec version again.
    Checked(CheckedMetadata<'a>),

    /// Spec version is not yet known and must be determined here.
    Raw(&'a RuntimeMetadataV14),
}

impl<'a> MetaInput<'a> {
    /// Transform `MetaInput` into `CheckedMetadata`.
    ///
    /// If `MetaInput` is `Raw`, search metadata for `System` pallet and
    /// `Version` constant within it, decode `Version` constant and find the
    /// field with `SpecVersion` content.
    pub(crate) fn checked(self) -> Result<CheckedMetadata<'a>, MetaVersionError> {
        match self {
            Self::Checked(checked_metadata) => Ok(checked_metadata),
            Self::Raw(meta_v14) => {
                let mut runtime_version_data_and_ty = None;
                let mut system_block = false;
                for pallet in meta_v14.pallets.iter() {
                    if pallet.name == "System" {
                        system_block = true;
                        for constant in pallet.constants.iter() {
                            if constant.name == "Version" {
                                runtime_version_data_and_ty =
                                    Some((constant.value.to_owned(), constant.ty))
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
                    Some((value, ty)) => match decode_all_as_type(&ty, &value, &meta_v14.types) {
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
                    },
                    None => return Err(MetaVersionError::NoVersionInConstants),
                }
                let version = match spec_version {
                    Some(a) => a,
                    None => return Err(MetaVersionError::NoSpecVersionIdentifier),
                };
                Ok(CheckedMetadata { meta_v14, version })
            }
        }
    }
}
