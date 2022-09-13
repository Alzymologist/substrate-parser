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

    #[error("Some call data remained unused after decoding.")]
    SomeDataNotUsedCall,

    #[error("Some extensions data remained unused after decoding.")]
    SomeDataNotUsedExtensions,

    #[error("Wrong chain. Apparent genesis hash in extensions (hex::encode(as_decoded.0)) does not match the expected one (hex::encode(expected.0)).")]
    WrongGenesisHash { as_decoded: H256, expected: H256 },

    #[error("Wrong metadata spec version. When decoding extensions data with metadata version {in_metadata}, the apparent spec version in extensions is {as_decoded}.")]
    WrongSpecVersion {
        as_decoded: String,
        in_metadata: String,
    },
}

/// Errors in data parsing.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ParserError {
    #[error("Remaining data too short for expected content.")]
    DataTooShort,

    #[error("Resolving type id {0} results in cycling.")]
    CyclicMetadata(u32),

    #[error("Expected compact, not found one.")]
    NoCompact,

    #[error("Declared type is not suitable BitStore type for BitVec.")]
    NotBitStoreType,

    #[error("Declared type is not suitable BitOrder type for BitVec.")]
    NotBitOrderType,

    #[error("Expected to use all data provided in decoding. Some data remained unused.")]
    SomeDataNotUsedBlob,

    #[error("Unable to decode data piece as {0}.")]
    TypeFailure(&'static str),

    #[error("Encountered unexpected Option<_> variant.")]
    UnexpectedOptionVariant,

    #[error("Encountered unexpected enum variant.")]
    UnexpectedEnumVariant,

    #[error("Unexpected type inside compact.")]
    UnexpectedCompactInsides,

    #[error("Unable to resolve type id {0} in metadata type registry.")]
    V14TypeNotResolved(u32),
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
