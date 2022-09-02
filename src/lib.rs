//! This crate is a parser for Substrate chain data. It could be used to
//! decode signable transactions, calls, events, storage items etc. with chain
//! metadata. Decoded data could be pattern matched or represented in readable
//! form.
//!
//! Currently only the most recent `RuntimeMetadata` version `V14` is supported
//! for the chain metadata, as only the `V14` has conveniently in-built types
//! database in it, thus allowing to track types using metadata itself without
//! any additional information.
//!
//! # Assumptions
//!
//! Chain data is [SCALE-encoded](https://docs.substrate.io/reference/scale-codec/).
//! Data blobs entering decoder are expected to be decoded completely: all
//! provided `Vec<u8>` must be used in decoding with no data remaining.
//!
//! For decoding the entry type (such as the type of particular storage item) or
//! the data internal structure used to find the entry type in metadata (as is
//! the case for signable transactions) must be known.
//!
//! Entry type gets resolved into constituting types with metadata in-built
//! types registry and appropriate `&[u8]` chunks get cut from input blob and
//! decoded. The process follows what the `decode` from the
//! [SCALE codec](parity_scale_codec) does, except the types that go into the
//! decoder are found dynamically during the decoding itself.
//!
//! ## Signable transactions
//!
//! Signable transaction consist of the call part and extensions part.
//!
//! Call part contains double SCALE-encoded call data. This means that the
//! SCALE-encoded call data is preceded with compact of the encoded call data
//! length. This length is used to separate encoded call data and extensions
//! data, and decode them independently.
//!
//! Call data is effectively an enum, and first `u8` of the encoded call is
//! pallet `index` in [`PalletMetadata`](frame_metadata::v14::PalletMetadata).
//! Enum describing the calls corresponding to this pallet has type found in
//! [`PalletCallMetadata`](frame_metadata::v14::PalletCallMetadata). Further
//! decoding uses the type information found.
//!
//! Remaining data is SCALE-encoded set of signable extensions, as declared in
//! [`ExtrinsicMetadata`](frame_metadata::v14::ExtrinsicMetadata). Chain genesis
//! hash must be found among the decoded extensions and must match the genesis
//! hash known for the chain. Spec version must be found among the decoded
//! extensions and must match the spec version derived from the provided
//! metadata. This is done to make sure that the correct metadata was used for
//! parsing.
//!
//! ## Storage items
//!
//! Storage items could be queried from chain via rpc calls, and the retrieved
//! SCALE-encoded data has a type declared in corresponding chain metadata
//! [`StorageEntryType`](frame_metadata::v14::StorageEntryType).
//!
//! # Parsed data and cards
//!
//! Parsing data with a given type results in [`ExtendedData`]. Parsing data as
//! a call results in [`Call`]. Both types are complex and may (and usually
//! do) contain layered parsed data inside. During parsing itself as much as
//! possible of internal data structure, identifiers and docs are preserved so
//! that it is easier to find information in parsed items or pattern-match them.
//!
//! All parsed results may be carded. Cards are **flat** formatted elements,
//! with type-associated information, that could be printed or otherwise
//! displayed to user. Each `Call` and `ExtendedData` gets carded into
//! `Vec<ExtendedCard>`.
//!
//! # Special types
//!
//! Types, as stored in the metadata types registry, have associated
//! [`Path`](scale_info::Path) information. The `ident` segment of the `Path` is
//! used to detect the special types.
//!
//! Some `Path` identifiers are used without further checking, such as
//! well-known array-based types (`AccountId32`, hashes, public keys, signatures
//! etc) or other types with known or easily determined encoded size, such as
//! `Era`, `PerThing` items etc.
//!
//! Other `Path` identifiers are checked first, and used only if the further
//! discovered type information matches the expected one, this is the case for
//! `Call`, `Event` and `Option`. If it does not match, the data is parsed as
//! is, i.e. without fitting into specific item format.
//!
//! Enums and structs contain sets of [`Field`](scale_info::Field)s. Field
//! `name` and `type_name` may also hint at type specialty information, although
//! less reliably than the `Path`. Such hints do not cause errors in parser flow
//! if appear unexpectedly, and just get ignored.
//!
//! Field could contain currency-related data. When carded and displayed,
//! currency is displayed with chain decimals and units only if encountered in
//! a particular set of pallets or in extensions.
#![deny(unused_crate_dependencies)]

use frame_metadata::v14::RuntimeMetadataV14;
use scale_info::interner::UntrackedSymbol;
use sp_core::H256;

pub mod cards;
use cards::{Call, ExtendedCard, ExtendedData};
pub mod compacts;
use compacts::get_compact;
mod decoding_sci;
pub use decoding_sci::{decode_as_call_v14, decode_with_type, Ty};
mod decoding_sci_ext;
pub use decoding_sci_ext::decode_ext_attempt;
pub mod error;
use error::{ParserError, SignableError};
pub mod printing_balance;
pub mod special_indicators;
use special_indicators::Propagated;
pub mod special_types;

#[cfg(test)]
mod tests;

/// Chain data necessary to display decoded data correctly.
pub struct ShortSpecs {
    pub base58prefix: u16,
    pub decimals: u8,
    pub genesis_hash: H256,
    pub name: String,
    pub unit: String,
}

/// Cut a signable transaction data into call part and extensions part.
pub fn cut_call_extensions(data: &mut Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), SignableError> {
    let call_length = get_compact::<u32>(data).map_err(|_| SignableError::CutSignable)? as usize;
    match data.get(..call_length) {
        Some(a) => Ok((a.to_vec(), data[call_length..].to_vec())),
        None => Err(SignableError::CutSignable),
    }
}

/// Signable transaction parsing outcome.
///
/// Extensions must be decoded. Call decoding may be successful or not.
#[derive(Debug)]
pub struct TransactionParsed {
    pub call_result: Result<Call, SignableError>,
    pub extensions: Vec<ExtendedData>,
}

/// Parse a signable transaction.
pub fn parse_transaction(
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
    version: u32,
    genesis_hash: H256,
) -> Result<TransactionParsed, SignableError> {
    // if unable to separate call date and extensions, then there is
    // some fundamental flaw is in transaction itself
    let (mut call_data, mut extensions_data) = cut_call_extensions(data)?;

    // try parsing extensions, check that spec version and genesis hash are
    // correct
    let extensions = decode_ext_attempt(&mut extensions_data, meta_v14, version, genesis_hash)?;

    // try parsing call data
    let call_result = decode_as_call_v14(&mut call_data, meta_v14);

    Ok(TransactionParsed {
        call_result,
        extensions,
    })
}

/// Display signable transaction, in readable form.
pub fn display_transaction(
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
    version: u32,
    short_specs: &ShortSpecs,
) -> Result<String, String> {
    let parsed = parse_transaction(data, meta_v14, version, short_specs.genesis_hash)
        .map_err(|e| e.to_string())?;

    let indent = 0;
    let mut extensions_set: Vec<ExtendedCard> = Vec::new();
    for extension in parsed.extensions.iter() {
        let addition_set = extension.card(indent, true, short_specs);
        if !addition_set.is_empty() {
            extensions_set.extend_from_slice(&addition_set)
        }
    }

    let mut extensions_printed = String::new();
    for (i, x) in extensions_set.iter().enumerate() {
        if i > 0 {
            extensions_printed.push('\n')
        }
        extensions_printed.push_str(&x.show());
    }
    let call_printed = match parsed.call_result {
        Ok(call_parsed) => {
            let call_set = call_parsed.card(indent, short_specs);
            let mut call_out = String::new();
            for (i, x) in call_set.iter().enumerate() {
                if i > 0 {
                    call_out.push('\n')
                }
                call_out.push_str(&x.show());
            }
            call_out
        }
        Err(e) => e.to_string(),
    };
    Ok(format!(
        "\nCall:\n\n{}\n\n\nExtensions:\n\n{}",
        call_printed, extensions_printed
    ))
}

/// Decode data blob with known type.
///
/// No check here for all data being used. This check must be added elsewhere.
pub fn decode_blob_as_type(
    ty_symbol: &UntrackedSymbol<std::any::TypeId>,
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
) -> Result<ExtendedData, ParserError> {
    decode_with_type(&Ty::Symbol(ty_symbol), data, meta_v14, Propagated::new())
}
