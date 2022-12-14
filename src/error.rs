//! Errors.
use primitive_types::H256;

use crate::std::string::String;

#[cfg(feature = "std")]
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[cfg(not(feature = "std"))]
use core::fmt::{Display, Formatter, Result as FmtResult};

/// Errors in signable transactions parsing.
#[derive(Debug, Eq, PartialEq)]
pub enum SignableError {
    CutSignable,
    ExtensionsList(ExtensionsError),
    ImmortalHashMismatch,
    MetaVersion(MetaVersionError),
    NoCallsInPallet(String),
    NotACall(String),
    PalletNotFound(u8),
    Parsing(ParserError),
    SomeDataNotUsedCall {
        from: usize,
        to: usize,
    },
    SomeDataNotUsedExtensions {
        from: usize,
    },
    WrongGenesisHash {
        as_decoded: H256,
        expected: H256,
    },
    WrongSpecVersion {
        as_decoded: String,
        in_metadata: String,
    },
}

impl SignableError {
    fn error_text(&self) -> String {
        match &self {
            SignableError::CutSignable => String::from("Unable to separate signable transaction data into call data and extensions data."),
            SignableError::ExtensionsList(extensions_error) => extensions_error.error_text(),
            SignableError::ImmortalHashMismatch => String::from("Extensions error. Block hash does not match the chain genesis hash in transaction with immortal `Era`."),
            SignableError::MetaVersion(meta_version_error) => format!("Unable to determine metadata spec version. {meta_version_error}"),
            SignableError::NoCallsInPallet(pallet_name) => format!("Unable to decode the call data of the signable transaction. Pallet {pallet_name} has no calls."),
            SignableError::NotACall(pallet_name) => format!("Unable to decode the call data of the signable transaction. Call type in pallet {pallet_name} is not an enum."),
            SignableError::PalletNotFound(index) => format!("Unable to decode the call data of the signable transaction. Metadata contains no pallet with index {index}."),
            SignableError::Parsing(parser_error) => format!("Parsing error. {parser_error}"),
            SignableError::SomeDataNotUsedCall { from, to } => format!("Some call data (input positions [{from}..{to}]) remained unused after decoding."),
            SignableError::SomeDataNotUsedExtensions { from } => format!("Some extensions data (input positions [{from}..]) remained unused after decoding."),
            SignableError::WrongGenesisHash { as_decoded, expected } => format!("Wrong chain. Apparent genesis hash in extensions {} does not match the expected one {}.", hex::encode(as_decoded.0), hex::encode(expected.0)),
            SignableError::WrongSpecVersion { as_decoded, in_metadata} => format!("Wrong metadata spec version. When decoding extensions data with metadata version {in_metadata}, the apparent spec version in extensions is {as_decoded}."),
        }
    }
}

/// Errors in storage entry parsing.
#[derive(Debug, Eq, PartialEq)]
pub enum StorageError {
    KeyPartHashMismatch,
    KeyPartsUnused,
    KeyShorterThanPrefix,
    MultipleHashesNotATuple,
    MultipleHashesNumberMismatch,
    ParsingKey(ParserError),
    ParsingValue(ParserError),
    PlainKeyExceedsPrefix,
}

impl StorageError {
    fn error_text(&self) -> String {
        match &self {
            StorageError::KeyPartHashMismatch => {
                String::from("Hash part of the storage key does not match the key data.")
            }
            StorageError::KeyPartsUnused => {
                String::from("During the storage key parsing a part of the key remained unused.")
            }
            StorageError::KeyShorterThanPrefix => {
                String::from("Provided storage key is shorter than the expected prefix.")
            }
            StorageError::MultipleHashesNotATuple => {
                String::from("Hashers length is not 1, but the key type is not a tuple.")
            }
            StorageError::MultipleHashesNumberMismatch => String::from(
                "Hashers length does not match the number of fields in a tuple key type.",
            ),
            StorageError::ParsingKey(parser_error) => {
                format!("Error parsing the storage key. {parser_error}")
            }
            StorageError::ParsingValue(parser_error) => {
                format!("Error parsing the storage value. {parser_error}")
            }
            StorageError::PlainKeyExceedsPrefix => {
                String::from("Plain storage key contains data other than the prefix.")
            }
        }
    }
}

/// Errors in data parsing.
#[derive(Debug, Eq, PartialEq)]
pub enum ParserError {
    DataTooShort {
        position: usize,
        minimal_length: usize,
    },
    CyclicMetadata {
        id: u32,
    },
    NoCompact {
        position: usize,
    },
    NotBitOrderType {
        id: u32,
    },
    NotBitStoreType {
        id: u32,
    },
    OutOfRange {
        position: usize,
        total_length: usize,
    },
    SomeDataNotUsedBlob {
        from: usize,
    },
    TypeFailure {
        position: usize,
        ty: &'static str,
    },
    UnexpectedCompactInsides {
        id: u32,
    },
    UnexpectedEnumVariant {
        position: usize,
    },
    UnexpectedOptionVariant {
        position: usize,
    },
    V14TypeNotResolved {
        id: u32,
    },
}

impl ParserError {
    fn error_text(&self) -> String {
        match &self {
            ParserError::DataTooShort { position, minimal_length } => format!("Data is too short for expected content. Expected at least {minimal_length} element(s) after position {position}."),
            ParserError::CyclicMetadata { id } => format!("Resolving type id {id} in metadata type registry results in cycling."),
            ParserError::NoCompact { position } => format!("Expected compact starting at position {position}, not found one."),
            ParserError::NotBitOrderType { id } => format!("BitVec type {id} in metadata type registry has unexpected BitOrder type."),
            ParserError::NotBitStoreType { id } => format!("BitVec type {id} in metadata type registry has unexpected BitStore type."),
            ParserError::OutOfRange { position, total_length } => format!("Position {position} is out of range for data length {total_length}."),
            ParserError::SomeDataNotUsedBlob { from } => format!("Some data (input positions [{from}..]) remained unused after decoding."),
            ParserError::TypeFailure { position, ty } => format!("Unable to decode data starting at position {position} as {ty}."),
            ParserError::UnexpectedCompactInsides { id } => format!("Compact type {id} in metadata type registry has unexpected type inside compact."),
            ParserError::UnexpectedEnumVariant { position } => format!("Encountered unexpected enum variant at position {position}."),
            ParserError::UnexpectedOptionVariant { position } => format!("Encountered unexpected Option<_> variant at position {position}."),
            ParserError::V14TypeNotResolved { id } => format!("Unable to resolve type id {id} in metadata type registry."),
        }
    }
}

/// Errors caused by [`RuntimeMetadataV14`](frame_metadata::v14::RuntimeMetadataV14)
/// extensions set.
///
/// Decoding signable transactions puts a set of requirements on the metadata
/// itself. Extensions are expected to contain:
///
/// - no more than one `Era`
/// - no more than one block hash
/// - metadata spec version (exactly once)
/// - chain genesis hash (exactly once)
///
/// Spec version of the metadata and genesis hash are required to check that the
/// correct metadata was used for signable transaction parsing.
///
/// If `Era` is encountered and immortal, block hash (if encountered) must be
/// checked to match the genesis hash.
#[derive(Debug, Eq, PartialEq)]
pub enum ExtensionsError {
    BlockHashTwice,
    EraTwice,
    GenesisHashTwice,
    NoGenesisHash,
    NoSpecVersion,
    SpecVersionTwice,
}

impl ExtensionsError {
    fn error_text(&self) -> String {
        match &self {
            ExtensionsError::BlockHashTwice => String::from("Signable transaction extensions contain more than one block hash entry."),
            ExtensionsError::EraTwice => String::from("Signable transaction extensions contain more than one `Era` entry."),
            ExtensionsError::GenesisHashTwice => String::from("Signable transaction extensions contain more than one genesis hash entry. Unable to verify that correct chain is used for parsing."),
            ExtensionsError::NoGenesisHash => String::from("Signable transaction extensions do not include chain genesis hash. Unable to verify that correct chain is used for parsing."),
            ExtensionsError::NoSpecVersion => String::from("Signable transaction extensions do not include metadata spec version. Unable to verify that correct metadata version is used for parsing."),
            ExtensionsError::SpecVersionTwice => String::from("Signable transaction extensions contain more than one metadata spec version. Unable to verify that correct metadata version is used for parsing."),
        }
    }
}

/// Error in metadata version constant search.
#[derive(Debug, Eq, PartialEq)]
pub enum MetaVersionError {
    NoSpecVersionIdentifier,
    NoSystemPallet,
    NoVersionInConstants,
    RuntimeVersionNotDecodeable,
    UnexpectedRuntimeVersionFormat,
}

impl MetaVersionError {
    fn error_text(&self) -> String {
        match &self {
            MetaVersionError::NoSpecVersionIdentifier => {
                String::from("No spec version found in decoded `Version` constant.")
            }
            MetaVersionError::NoSystemPallet => String::from("No `System` pallet in metadata."),
            MetaVersionError::NoVersionInConstants => {
                String::from("No `Version` constant in metadata `System` pallet.")
            }
            MetaVersionError::RuntimeVersionNotDecodeable => String::from(
                "`Version` constant from metadata `System` pallet could not be decoded.",
            ),
            MetaVersionError::UnexpectedRuntimeVersionFormat => {
                String::from("Decoded `Version` constant is not a composite.")
            }
        }
    }
}

/// Implement [`Display`] for errors in both `std` and `no_std` cases.
/// Implement `Error` for `std` case.
macro_rules! impl_display_and_error {
    ($($ty: ty), *) => {
        $(
            impl Display for $ty {
                fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                    write!(f, "{}", self.error_text())
                }
            }

            #[cfg(feature = "std")]
            impl Error for $ty {
                fn source(&self) -> Option<&(dyn Error + 'static)> {
                    None
                }
            }
        )*
    }
}

impl_display_and_error!(
    ExtensionsError,
    MetaVersionError,
    ParserError,
    SignableError,
    StorageError
);
