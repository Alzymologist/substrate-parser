//! Errors.
use external_memory_tools::{BufferError, ExternalMemory};
use primitive_types::H256;

use crate::std::string::String;

#[cfg(feature = "std")]
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[cfg(not(feature = "std"))]
use core::fmt::{Display, Formatter, Result as FmtResult};

use crate::traits::AsMetadata;

/// Errors in signable transactions parsing.
#[derive(Debug, Eq, PartialEq)]
pub enum SignableError<E, M>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    CutSignable,
    ExtensionsList(ExtensionsError),
    ImmortalHashMismatch,
    MetaStructure(M::MetaStructureError),
    NotACall(u32),
    Parsing(ParserError<E>),
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

impl<E, M> SignableError<E, M>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    fn error_text(&self) -> String {
        match &self {
            SignableError::CutSignable => String::from("Unable to separate signable transaction data into call data and extensions data."),
            SignableError::ExtensionsList(extensions_error) => extensions_error.error_text(),
            SignableError::ImmortalHashMismatch => String::from("Extensions error. Block hash does not match the chain genesis hash in transaction with immortal `Era`."),
            SignableError::MetaStructure(meta_structure_error) => format!("Unexpected structure of the metadata. {meta_structure_error}"),
            SignableError::NotACall(all_calls_ty_id) => format!("Decoded signable transaction is not a call. Unexpected structure of calls descriptor type {all_calls_ty_id}."),
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
pub enum StorageError<E: ExternalMemory> {
    KeyPartHashMismatch,
    KeyPartsUnused,
    KeyShorterThanPrefix,
    MultipleHashesNotATuple,
    MultipleHashesNumberMismatch,
    ParsingKey(ParserError<E>),
    ParsingValue(ParserError<E>),
    PlainKeyExceedsPrefix,
}

impl<E: ExternalMemory> StorageError<E> {
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
pub enum ParserError<E: ExternalMemory> {
    Buffer(BufferError<E>),
    Registry(RegistryError),
    NoCompact { position: usize },
    SomeDataNotUsedBlob { from: usize },
    TypeFailure { position: usize, ty: &'static str },
    UnexpectedEnumVariant { position: usize },
}

impl<E: ExternalMemory> ParserError<E> {
    fn error_text(&self) -> String {
        match &self {
            ParserError::Buffer(buffer_error) => format!("{buffer_error}"),
            ParserError::Registry(registry_error) => {
                format!("{registry_error}")
            }
            ParserError::NoCompact { position } => {
                format!("Expected compact starting at position {position}, not found one.")
            }
            ParserError::SomeDataNotUsedBlob { from } => {
                format!("Some data (input positions [{from}..]) remained unused after decoding.")
            }
            ParserError::TypeFailure { position, ty } => {
                format!("Unable to decode data starting at position {position} as {ty}.")
            }
            ParserError::UnexpectedEnumVariant { position } => {
                format!("Encountered unexpected enum variant at position {position}.")
            }
        }
    }
}

/// Errors in metadata types registry.
#[derive(Debug, Eq, PartialEq)]
pub enum RegistryError {
    CyclicMetadata { id: u32 },
    ExtrinsicNoCallParam,
    NotBitOrderType { id: u32 },
    NotBitStoreType { id: u32 },
    TypeNotResolved { id: u32 },
    UnexpectedCompactInsides { id: u32 },
    UnexpectedExtrinsicType { extrinsic_ty_id: u32 },
}

impl RegistryError {
    fn error_text(&self) -> String {
        match &self {
            RegistryError::CyclicMetadata { id } => format!("Resolving type id {id} in metadata type registry results in cycling."),
            RegistryError::ExtrinsicNoCallParam => String::from("Extrinsic type in provided metadata has no specified call parameter."),
            RegistryError::NotBitOrderType { id } => format!("BitVec type {id} in metadata type registry has unexpected BitOrder type."),
            RegistryError::NotBitStoreType { id } => format!("BitVec type {id} in metadata type registry has unexpected BitStore type."),
            RegistryError::TypeNotResolved { id } => format!("Unable to resolve type id {id} in metadata type registry."),
            RegistryError::UnexpectedCompactInsides { id } => format!("Compact type {id} in metadata type registry has unexpected type inside compact."),
            RegistryError::UnexpectedExtrinsicType { extrinsic_ty_id } => format!("Decoding is based on assumption that extrinsic type resolves into a SCALE-encoded opaque `Vec<u8>`. Unexpected type description is found for type {extrinsic_ty_id} in metadata type registry."),
        }
    }
}

/// Errors caused by the extensions set.
///
/// Decoding signable transactions puts a set of requirements on the metadata
/// itself. Extensions are expected to contain:
///
/// - no more than one `Era`
/// - no more than one block hash
/// - metadata `spec_version` (exactly once)
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

/// Errors in expected structure of V14 metadata.
#[derive(Debug, Eq, PartialEq)]
pub enum MetaStructureErrorV14 {
    ExtrinsicTypeNotResolved(RegistryError),
    NoAddressParam,
    NoCallParam,
    NoExtraParam,
    NoSignatureParam,
    UnexpectedExtrinsicType { extrinsic_ty_id: u32 },
    Version(MetaVersionErrorPallets),
}

impl MetaStructureErrorV14 {
    fn error_text(&self) -> String {
        match &self {
            MetaStructureErrorV14::ExtrinsicTypeNotResolved(registry_error_extrinsic) => format!("Unable to resolve in registry the chain extrinsic type. {registry_error_extrinsic}"),
            MetaStructureErrorV14::NoAddressParam => String::from("Unchecked extrinsic type in provided metadata has no specified address parameter."),
            MetaStructureErrorV14::NoCallParam => String::from("Unchecked extrinsic type in provided metadata has no specified call parameter."),
            MetaStructureErrorV14::NoExtraParam => String::from("Unchecked extrinsic type in provided metadata has no specified extra parameter."),
            MetaStructureErrorV14::NoSignatureParam => String::from("Unchecked extrinsic type in provided metadata has no specified signature parameter."),
            MetaStructureErrorV14::UnexpectedExtrinsicType { extrinsic_ty_id } => format!("Decoding is based on assumption that extrinsic type resolves into a SCALE-encoded opaque `Vec<u8>`. Unexpected type description is found for type {extrinsic_ty_id} in metadata type registry."),
            MetaStructureErrorV14::Version(meta_version_error_pallets) => format!("{meta_version_error_pallets}"),
        }
    }
}

impl From<MetaVersionErrorPallets> for MetaStructureErrorV14 {
    fn from(meta_version_error_pallets: MetaVersionErrorPallets) -> Self {
        MetaStructureErrorV14::Version(meta_version_error_pallets)
    }
}

impl From<RegistryError> for MetaStructureErrorV14 {
    fn from(registry_error_extrinsic: RegistryError) -> Self {
        MetaStructureErrorV14::ExtrinsicTypeNotResolved(registry_error_extrinsic)
    }
}

/// Error in metadata version constant search.
#[derive(Debug, Eq, PartialEq)]
pub enum MetaVersionErrorPallets {
    NoSpecNameIdentifier,
    NoSpecVersionIdentifier,
    NoSystemPallet,
    NoVersionInConstants,
    RuntimeVersionNotDecodeable,
    SpecNameIdentifierTwice,
    SpecVersionIdentifierTwice,
    UnexpectedRuntimeVersionFormat,
}

impl MetaVersionErrorPallets {
    fn error_text(&self) -> String {
        match &self {
            MetaVersionErrorPallets::NoSpecNameIdentifier => {
                String::from("No spec name found in decoded `Version` constant.")
            }
            MetaVersionErrorPallets::NoSpecVersionIdentifier => {
                String::from("No spec version found in decoded `Version` constant.")
            }
            MetaVersionErrorPallets::NoSystemPallet => {
                String::from("No `System` pallet in metadata.")
            }
            MetaVersionErrorPallets::NoVersionInConstants => {
                String::from("No `Version` constant in metadata `System` pallet.")
            }
            MetaVersionErrorPallets::RuntimeVersionNotDecodeable => String::from(
                "`Version` constant from metadata `System` pallet could not be decoded.",
            ),
            MetaVersionErrorPallets::SpecNameIdentifierTwice => String::from(
                "Spec name associated identifier found twice when decoding `Version` constant.",
            ),
            MetaVersionErrorPallets::SpecVersionIdentifierTwice => String::from(
                "Spec version associated identifier found twice when decoding `Version` constant.",
            ),
            MetaVersionErrorPallets::UnexpectedRuntimeVersionFormat => {
                String::from("Decoded `Version` constant is not a composite.")
            }
        }
    }
}

/// Error in parsing of an unchecked extrinsic.
#[derive(Debug, Eq, PartialEq)]
pub enum UncheckedExtrinsicError<E: ExternalMemory, M: AsMetadata<E>> {
    FormatNoCompact,
    MetaStructure(M::MetaStructureError),
    Parsing(ParserError<E>),
    VersionMismatch { version_byte: u8, version: u8 },
    UnexpectedCallTy { call_ty_id: u32 },
}

impl<E, M> UncheckedExtrinsicError<E, M>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    fn error_text(&self) -> String {
        match &self {
            UncheckedExtrinsicError::FormatNoCompact => String::from("Unchecked extrinsic was expected to be a SCALE-encoded opaque `Vec<u8>`. Have not found a compact indicating vector length."),
            UncheckedExtrinsicError::MetaStructure(meta_structure_error) => format!("Unexpected structure of the metadata. {meta_structure_error}"),
            UncheckedExtrinsicError::Parsing(parser_error) => format!("Error parsing unchecked extrinsic data. {parser_error}"),
            UncheckedExtrinsicError::VersionMismatch { version_byte, version } => format!("Version byte in unchecked extrinsic {version_byte} does not match with version {version} from provided metadata. Last 7 bits were expected to be identical."),
            UncheckedExtrinsicError::UnexpectedCallTy { call_ty_id } => format!("Parameter type for call {call_ty_id} in metadata type registry is not a call type, and does not match known call type descriptors."),
        }
    }
}

/// Implement [`Display`] and `Error` (`std` only). Errors with no generics.
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
    MetaStructureErrorV14,
    MetaVersionErrorPallets,
    RegistryError
);

/// Implement [`Display`] and `Error` (`std` only). Errors with single `<E>` generic.
macro_rules! impl_display_and_error_gen {
    ($($ty: ty), *) => {
        $(
            impl <E: ExternalMemory> Display for $ty {
                fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                    write!(f, "{}", self.error_text())
                }
            }

            #[cfg(feature = "std")]
            impl <E: ExternalMemory> Error for $ty {
                fn source(&self) -> Option<&(dyn Error + 'static)> {
                    None
                }
            }
        )*
    }
}

impl_display_and_error_gen!(ParserError<E>, StorageError<E>);

impl<E: ExternalMemory> From<BufferError<E>> for ParserError<E> {
    fn from(buffer_error: BufferError<E>) -> Self {
        ParserError::Buffer(buffer_error)
    }
}

impl<E: ExternalMemory> From<RegistryError> for ParserError<E> {
    fn from(registry_error: RegistryError) -> Self {
        ParserError::Registry(registry_error)
    }
}

/// Implement [`Display`], `Error` (`std` only), and `From<ParserError<E>>` conversion.
macro_rules! impl_display_error_from_2gen {
    ($($ty: ty), *) => {
        $(
            impl <E, M> Display for $ty
            where
                E: ExternalMemory,
                M: AsMetadata<E>,
            {
                fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                    write!(f, "{}", self.error_text())
                }
            }

            #[cfg(feature = "std")]
            impl <E, M> Error for $ty
            where
                E: ExternalMemory,
                M: AsMetadata<E>,
            {
                fn source(&self) -> Option<&(dyn Error + 'static)> {
                    None
                }
            }

            impl <E, M> From<ParserError<E>> for $ty
            where
                E: ExternalMemory,
                M: AsMetadata<E>,
            {
                fn from(parser_error: ParserError<E>) -> Self {
                    <$ty>::Parsing(parser_error)
                }
            }
        )*
    }
}

impl_display_error_from_2gen!(SignableError<E, M>, UncheckedExtrinsicError<E, M>);
