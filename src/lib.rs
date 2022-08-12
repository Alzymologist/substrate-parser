//! This crate is a transaction parser used by
//! [Signer](https://github.com/paritytech/parity-signer).
//!
//! # Scope
//!
//! Signer allows to sign only the transactions that were successfully parsed
//! and were approved by user after checking the transaction contents.
//!
//! Transactions are read by the Signer as QR codes with data having following
//! structure:
//!
//! <table>
//!     <tr>
//!         <td>prelude</td>
//!         <td>public key</td>
//!         <td>SCALE-encoded call data</td>
//!         <td>SCALE-encoded extensions</td>
//!         <td>network genesis hash</td>
//!     </tr>
//! </table>
//!
//! This crate deals with decoding and presenting in a readable format the call
//! data and extensions data, and processes only the
//!
//! <table>
//!     <tr>
//!         <td>SCALE-encoded call data</td>
//!         <td>SCALE-encoded extensions</td>
//!     </tr>
//! </table>
//!
//! part.
//!
//! The ultimate goal here is to show the contents of the call and the
//! extensions, not perform any operations on them, and this crate is not
//! intended to keep track of the types used in call generation.
//!
//! # Features
//!
//! Default feature `"standalone"` allows to operate the parser as a standalone
//! tool to parse the contents of transactions.
//!
//! Signer itself uses `parser` crate with default features disabled.
//!
//! # How the parser works
//!
//! Call data and extensions data in transactions are
//! [SCALE-encoded](https://docs.substrate.io/reference/scale-codec/).
//!
//! Parsing always starts with separating call data and extensions data.
//!
//! Call data is `Vec<u8>`. **SCALE-encoded** call data, that is a part of the
//! transaction data, is the same `Vec<u8>` prefixed with compact of the call
//! data length. After the first compact is found, the data gets cut into call
//! data and the extensions data, that get processed separately.
//!
//! In decoding both call and extensions data the `Vec<u8>` enters the decoder,
//! and gets pieces cut off byte-by-byte starting from the first. This
//! processing follows what the `decode` from the [`parity_scale_codec`] does,
//! however, the types that go into the decoder are found dynamically during the
//! decoding itself. Generally, first, the type is found from the metadata, then
//! the bytes corresponding to the encoded value are cut from the entered data,
//! decoded and transformed into displayable [`OutputCard`].
//!
//! Notably, the decoding operates differently for different
//! [`RuntimeMetadata`](frame_metadata::RuntimeMetadata) variants. Signer can
//! work with metadata `V12`, `V13` and `V14`. Of those, only `V14`, i.e.
//! [`RuntimeMetadataV14`] has types described inside the metadata itself.
//! `V12` and `V13` have only type text descriptors, and the types meaning has
//! to be inferred from elsewhere, therefore, additional types description
//! dataset is needed to parse transactions made with metadata runtime versions
//! below `V14`.
//!
//! ## Decoding extensions
//!
//! Decoding starts with the extensions, as the extensions contain the metadata
//! version that must match the version of the metadata used to decode both the
//! extensions and the call data.
//!
//! Extensions in metadata `V12` and `V13` are described in the metadata as
//! `ExtrinsicMetadata` in `extrinsic` field of the `RuntimeMetadataV12` and
//! `RuntimeMetadataV13`. Field `signed_extensions` contain text identifier set
//! for extensions, that in principle can vary between the metadata. Here for
//! older metadata static extension set is used, matching the only ever
//! encountered in Substrate networks extensions.
//!
//! In metadata `V14` the extensions are described in `extrinsic` field of the
//! `RuntimeMetadataV14`, and have types resolvable in the associated with the
//! metadata types registry. Set of extensions in `signed_extensions` field of
//! the [`ExtrinsicMetadata`](frame_metadata::v14::ExtrinsicMetadata) is scanned
//! twice: first, for the types in field `ty`, then for the types in the field
//! `additional_signed` of the
//! [`SignedExtensionsMetadata`](frame_metadata::v14::SignedExtensionMetadata).
//! The extensions for most `V14` metadata are matching the static ones used for
//! `V12` and `V13`, however, as the types could be easily interpreted,
//! potentially changeable construction is used here.
//!
//! ## Decoding call data
//!
//! Once the extensions are decoded and the metadata version in transaction is
//! asserted to match the metadata version from the metadata itself, the call
//! can be decoded.
//!
//! Both the call and the extensions decoding must use all the bytes that were
//! initially in the input.
//!
//! The call data always starts with pallet number, the index of the pallet in
//! which the call was created. In a sense, the call data is encoded enum data
//! with pallet being the enum variant used. Pallet index is the first byte
//! of the data, it is declared to be `u8` in `V12`
//! [`ModuleMetadata`](frame_metadata::v12::ModuleMetadata), `V13`
//! [`ModuleMetadata`](frame_metadata::v13::ModuleMetadata) and `V14`
//! [`PalletMetadata`](frame_metadata::v14::PalletMetadata).
//!
//! The pallet index is the decoding entry point for all runtime metadata
//! versions. The pallets available in the metadata are scanned to find the
//! pallet with correct index.
//!
//! ### Metadata `V14`
//!
//! For `V14` runtime metadata version the remaining data is then processed as
//! enum, with the type specified in `calls` field of the
//! [`PalletMetadata`](frame_metadata::v14::PalletMetadata). Enum variant has
//! field(s) with specified types, all of which are resolved in the types
//! registry, get bytes cut off from the remaining call data to decode with the
//! type found, and produce [`OutputCard`]s that are added to output set.
//!
//! ### Metadata `V12` and `V13`
//!
//! For `V12` and `V13` runtime metadata version the correct call variant and
//! its [`FunctionMetadata`](frame_metadata::v12::FunctionMetadata) in is found
//! by the ordinal number of the call in the vector in `calls` field of
//! `ModuleMetadata`. Arguments associated with the call (types and variable
//! names) are found in call-associated set of
//! [`FunctionArgumentMetadata`](frame_metadata::v12::FunctionMetadata) in
//! `arguments` field of the `FunctionMetadata`. Arguments are used in the same
//! order as they are listed.
//!
//! The text type descriptors are parsed using Regex (interpreting `Option`,
//! `Vec`, tuple fields etc) down to types that **have** to be known and then
//! those are used. The types information that is by default on record in the
//! Signer, contains description of the types that were used at the time of the
//! parser drafting in Westend. Polkadot, Kusama and Rococo networks, when those
//! still used metadata below `V14`. Types pre-`V14` were quite stable, so most
//! of the trivial transactions are expected to be parsed.
//!
//! If one of the encountered type is not described, Signer will not be able to
//! parse the transaction. In this case users are encouraged to update the types
//! information.
//!
//! For each argument an [`OutputCard`] is produces and added to the output set.
#![deny(unused_crate_dependencies)]

use frame_metadata::v14::RuntimeMetadataV14;
//#[cfg(feature = "standalone")]
//use frame_metadata::RuntimeMetadata;
//use parity_scale_codec::{Decode, DecodeAll, Encode};
//use scale_info::{form::PortableForm, Type};
use scale_info::interner::UntrackedSymbol;
use sp_core::H256;
//use sp_runtime::generic::Era;

//#[cfg(feature = "standalone")]
//use defaults::default_types_vec;
//#[cfg(feature = "standalone")]
//use definitions::metadata::info_from_metadata;
use definitions::{
    network_specs::ShortSpecs,
//    types::TypeEntry,
};

pub mod cards;
use cards::{Call, ExtendedData};
//mod decoding_older;
//use decoding_older::process_as_call;
pub mod decoding_commons;
use decoding_commons::get_compact;
mod decoding_sci;
pub use decoding_sci::{decode_as_call_v14, decode_with_type};
//use decoding_sci::{decoding_sci_entry_point, decoding_sci_complete, CallExpectation};
mod decoding_sci_ext;
pub use decoding_sci_ext::decode_ext_attempt;
pub mod error;
#[cfg(feature = "standalone")]
use error::{Error, ParserError};
//pub mod method;
//use method::OlderMeta;
pub mod special;
use special::Propagated;
#[cfg(feature = "standalone")]
#[cfg(test)]
mod tests;
/*
/// Parse call data with suitable network [`MetadataBundle`] and [`ShortSpecs`].
pub fn parse_method(
    method_data: &mut Vec<u8>,
    metadata_bundle: &MetadataBundle,
) -> Result<Vec<OutputCard>, ParserError> {
    let start_indent = 0;
    let out = match metadata_bundle {
        MetadataBundle::Older {
            older_meta,
            types,
            network_version: _,
        } => process_as_call(method_data, older_meta, types, start_indent)?,
        MetadataBundle::Sci {
            meta_v14,
            network_version: _,
        } => decoding_sci_entry_point(method_data, meta_v14, start_indent)?,
    };
    if !method_data.is_empty() {
        return Err(ParserError::Decoding(
            ParserDecodingError::SomeDataNotUsedMethod,
        ));
    }
    Ok(out)
}

/// Statically determined extensions for `V12` and `V13` metadata.
#[derive(Debug, Decode, Encode)]
struct ExtValues {
    era: Era,
    #[codec(compact)]
    nonce: u64,
    #[codec(compact)]
    tip: u128,
    metadata_version: u32,
    tx_version: u32,
    genesis_hash: H256,
    block_hash: H256,
}

/// Parse extensions.
pub fn parse_extensions(
    extensions_data: &mut Vec<u8>,
    metadata_bundle: &MetadataBundle,
    short_specs: &ShortSpecs,
    optional_mortal_flag: Option<bool>,
) -> Result<Vec<OutputCard>, ParserError> {
    let indent = 0;
    let (era, block_hash, cards) = match metadata_bundle {
        MetadataBundle::Older {
            older_meta: _,
            types: _,
            network_version,
        } => {
            let ext = match <ExtValues>::decode_all(&mut &extensions_data[..]) {
                Ok(a) => a,
                Err(_) => return Err(ParserError::Decoding(ParserDecodingError::ExtensionsOlder)),
            };
            if ext.genesis_hash != short_specs.genesis_hash {
                return Err(ParserError::Decoding(
                    ParserDecodingError::GenesisHashMismatch,
                ));
            }
            if network_version != &ext.metadata_version {
                return Err(ParserError::WrongNetworkVersion {
                    as_decoded: ext.metadata_version.to_string(),
                    in_metadata: network_version.to_owned(),
                });
            }
            let cards = vec![
                OutputCard {
                    card: ParserCard::Era(ext.era),
                    indent,
                },
                OutputCard {
                    card: ParserCard::PrimitiveU64 {
                        value: ext.nonce,
                        specialty: Specialty::Nonce,
                    },
                    indent,
                },
                OutputCard {
                    card: ParserCard::PrimitiveU128 {
                        value: ext.tip,
                        specialty: Specialty::Tip,
                    },
                    indent,
                },
                OutputCard {
                    card: ParserCard::PrimitiveU32 {
                        value: ext.metadata_version,
                        specialty: Specialty::SpecVersion,
                    },
                    indent,
                },
                OutputCard {
                    card: ParserCard::PrimitiveU32 {
                        value: ext.tx_version,
                        specialty: Specialty::TxVersion,
                    },
                    indent,
                },
                OutputCard {
                    card: ParserCard::BlockHash(ext.block_hash),
                    indent,
                },
            ];
            (ext.era, ext.block_hash, cards)
        }
        MetadataBundle::Sci {
            meta_v14,
            network_version,
        } => {
            let mut ext = Ext::init(short_specs.genesis_hash);
            let extensions_decoded =
                decode_ext_attempt(extensions_data, &mut ext, meta_v14, indent)?;
            if let Some(genesis_hash) = ext.found_ext.genesis_hash {
                if genesis_hash != short_specs.genesis_hash {
                    return Err(ParserError::Decoding(
                        ParserDecodingError::GenesisHashMismatch,
                    ));
                }
            }
            let block_hash = match ext.found_ext.block_hash {
                Some(a) => a,
                None => {
                    return Err(ParserError::FundamentallyBadV14Metadata(
                        ParserMetadataError::NoBlockHash,
                    ))
                }
            };
            let era = match ext.found_ext.era {
                Some(a) => a,
                None => {
                    return Err(ParserError::FundamentallyBadV14Metadata(
                        ParserMetadataError::NoEra,
                    ))
                }
            };
            match ext.found_ext.network_version_printed {
                Some(a) => {
                    if a != network_version.to_string() {
                        return Err(ParserError::WrongNetworkVersion {
                            as_decoded: a,
                            in_metadata: network_version.to_owned(),
                        });
                    }
                }
                None => {
                    return Err(ParserError::FundamentallyBadV14Metadata(
                        ParserMetadataError::NoVersionExt,
                    ))
                }
            }
            if !extensions_data.is_empty() {
                return Err(ParserError::Decoding(
                    ParserDecodingError::SomeDataNotUsedExtensions,
                ));
            }
            (era, block_hash, extensions_decoded)
        }
    };
    if let Era::Immortal = era {
        if short_specs.genesis_hash != block_hash {
            return Err(ParserError::Decoding(
                ParserDecodingError::ImmortalHashMismatch,
            ));
        }
        if let Some(true) = optional_mortal_flag {
            return Err(ParserError::Decoding(
                ParserDecodingError::UnexpectedImmortality,
            ));
        }
    }
    if let Era::Mortal(_, _) = era {
        if let Some(false) = optional_mortal_flag {
            return Err(ParserError::Decoding(
                ParserDecodingError::UnexpectedMortality,
            ));
        }
    }
    Ok(cards)
}
*/
/// Separate call data and extensions data based on the call data length
/// declared as a compact.
pub fn cut_method_extensions(data: &mut Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), ParserError> {
    let method_length =
        get_compact::<u32>(data).map_err(|_| ParserError::SeparateMethodExtensions)? as usize;
    if !data.is_empty() {
        match data.get(..method_length) {
            Some(a) => Ok((a.to_vec(), data[method_length..].to_vec())),
            None => Err(ParserError::SeparateMethodExtensions),
        }
    } else if method_length != 0 {
        Err(ParserError::SeparateMethodExtensions)
    } else {
        Ok((Vec::new(), data.to_vec()))
    }
}

#[derive(Debug)]
pub struct TransactionParsed {
    pub call_result: Result<Call, ParserError>,
    pub extensions: Vec<ExtendedData>,
}

#[cfg(feature = "standalone")]
/// Parse transaction with given metadata and network specs. For standalone
/// parser.
pub fn parse_transaction(
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
    version: u32,
    genesis_hash: H256,
) -> Result<TransactionParsed, ParserError> {

    // if unable to separate method date and extensions, then some fundamental flaw is in transaction itself
    let (mut call_data, mut extensions_data) = cut_method_extensions(data)?;

    // try parsing extensions, if is works, the version and extensions are correct
    let extensions = decode_ext_attempt(&mut extensions_data, meta_v14, version, genesis_hash)?;

    // try parsing method
    let call_result = decode_as_call_v14(&mut call_data, meta_v14);

    Ok(TransactionParsed{
        call_result,
        extensions,
    })
}

#[cfg(feature = "standalone")]
/// Parse transaction with given metadata and network specs. For standalone
/// parser.
pub fn display_transaction(
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
    version: u32,
    short_specs: &ShortSpecs,
) -> Result<String, String> {

    let parsed = parse_transaction(data, meta_v14, version, short_specs.genesis_hash).map_err(|e| Error::Parser(e).show())?;
    let mut extensions_printed = String::new();
    let indent = 0;
    let printed_extensions = parsed.extensions
        .iter()
        .map(|x| x.data.show(indent, short_specs, true))
        .filter(|x| !x.is_empty());
    for (i, x) in printed_extensions.enumerate() {
        if i>0 {extensions_printed.push('\n')}
        extensions_printed.push_str(&x);
    }
    let call_printed = match parsed.call_result {
        Ok(call_parsed) => call_parsed.show(indent, short_specs),
        Err(e) => e.show(),
    };
    Ok(format!(
        "\nCall:\n\n{}\n\n\nExtensions:\n\n{}",
        call_printed, extensions_printed
    ))
}

/// Decoder for random blob.
///
/// No check here for all data being used. This check must be added elsewhere.
pub fn decode_blob_as_type(ty_symbol: &UntrackedSymbol<std::any::TypeId>, data: &mut Vec<u8>, meta_v14: &RuntimeMetadataV14) -> Result<ExtendedData, ParserError> {
    decode_with_type(
        ty_symbol,
        data,
        meta_v14,
        Propagated::new(),
    )
}

