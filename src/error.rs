//! Errors.
use sp_core::H256;

/// Errors in signable transactions parsing.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignableError {
    #[error("Unable to separate signable transaction data into call data and extensions data.")]
    CutSignable,

    #[error("{0}")]
    ExtensionsList(ExtensionsError),

    #[error("Extensions error. Block hash does not match the chain genesis hash in transaction with immortal `Era`.")]
    ImmortalHashMismatch,

    #[error("Unable to determine metadata spec version. {0}")]
    MetaVersion(MetaVersionError),

    #[error(
        "Unable to decode the call data of the signable transaction. Pallet {0} has no calls."
    )]
    NoCallsInPallet(String),

    #[error("Unable to decode the call data of the signable transaction. Call type in pallet {0} is not an enum.")]
    NotACall(String),

    #[error("Unable to decode the call data of the signable transaction. Metadata contains no pallet with index {0}.")]
    PalletNotFound(u8),

    #[error("Parsing error. {0}")]
    Parsing(ParserError),

    #[error("Some call data (input positions [{from}..{to}]) remained unused after decoding.")]
    SomeDataNotUsedCall { from: usize, to: usize },

    #[error("Some extensions data (input positions [{from}..]) remained unused after decoding.")]
    SomeDataNotUsedExtensions { from: usize },

    #[error("Wrong chain. Apparent genesis hash in extensions {} does not match the expected one {}.", hex::encode(as_decoded.0), hex::encode(expected.0))]
    WrongGenesisHash { as_decoded: H256, expected: H256 },

    #[error("Wrong metadata spec version. When decoding extensions data with metadata version {in_metadata}, the apparent spec version in extensions is {as_decoded}.")]
    WrongSpecVersion {
        as_decoded: String,
        in_metadata: String,
    },
}

/// Errors in storage entry parsing.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageError {
    #[error("Hash part of the storage key does not match the key data.")]
    KeyPartHashMismatch,

    #[error("During the storage key parsing a part of the key remained unused.")]
    KeyPartsUnused,

    #[error("Provided storage key is shorter than the expected prefix.")]
    KeyShorterThanPrefix,

    #[error("Hashers length is not 1, but the key type is not a tuple.")]
    MultipleHashesNotATuple,

    #[error("Hashers length does not match the number of fields in a tuple key type.")]
    MultipleHashesNumberMismatch,

    #[error("Error parsing the storage key. {0}")]
    ParsingKey(ParserError),

    #[error("Error parsing the storage value. {0}")]
    ParsingValue(ParserError),

    #[error("Plain storage key contains data other than the prefix.")]
    PlainKeyExceedsPrefix,
}

/// Errors in data parsing.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ParserError {
    #[error("Data is too short for expected content. Expected at least {minimal_length} element(s) after position {position}.")]
    DataTooShort {
        position: usize,
        minimal_length: usize,
    },

    #[error("Resolving type id {id} in metadata type registry results in cycling.")]
    CyclicMetadata { id: u32 },

    #[error("Expected compact starting at position {position}, not found one.")]
    NoCompact { position: usize },

    #[error("BitVec type {id} in metadata type registry has unexpected BitOrder type.")]
    NotBitOrderType { id: u32 },

    #[error("BitVec type {id} in metadata type registry has unexpected BitStore type.")]
    NotBitStoreType { id: u32 },

    #[error("Position {position} is out of range for data length {total_length}.")]
    OutOfRange {
        position: usize,
        total_length: usize,
    },

    #[error("Some data (input positions [{from}..]) remained unused after decoding.")]
    SomeDataNotUsedBlob { from: usize },

    #[error("Unable to decode data starting at position {position} as {ty}.")]
    TypeFailure { position: usize, ty: &'static str },

    #[error("Compact type {id} in metadata type registry has unexpected type inside compact.")]
    UnexpectedCompactInsides { id: u32 },

    #[error("Encountered unexpected enum variant at position {position}.")]
    UnexpectedEnumVariant { position: usize },

    #[error("Encountered unexpected Option<_> variant at position {position}.")]
    UnexpectedOptionVariant { position: usize },

    #[error("Unable to resolve type id {id} in metadata type registry.")]
    V14TypeNotResolved { id: u32 },
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
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExtensionsError {
    #[error("Signable transaction extensions contain more than one block hash entry.")]
    BlockHashTwice,

    #[error("Signable transaction extensions contain more than one `Era` entry.")]
    EraTwice,

    #[error("Signable transaction extensions contain more than one genesis hash entry. Unable to verify that correct chain is used for parsing.")]
    GenesisHashTwice,

    #[error("Signable transaction extensions do not include chain genesis hash. Unable to verify that correct chain is used for parsing.")]
    NoGenesisHash,

    #[error("Signable transaction extensions do not include metadata spec version. Unable to verify that correct metadata version is used for parsing.")]
    NoSpecVersion,

    #[error("Signable transaction extensions contain more than one metadata spec version. Unable to verify that correct metadata version is used for parsing.")]
    SpecVersionTwice,
}

/// Error in metadata version constant search.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum MetaVersionError {
    #[error("No spec version found in decoded `Version` constant.")]
    NoSpecVersionIdentifier,

    #[error("No `System` pallet in metadata.")]
    NoSystemPallet,

    #[error("No `Version` constant in metadata `System` pallet.")]
    NoVersionInConstants,

    #[error("`Version` constant from metadata `System` pallet could not be decoded.")]
    RuntimeVersionNotDecodeable,

    #[error("Decoded `Version` constant is not a composite.")]
    UnexpectedRuntimeVersionFormat,
}
