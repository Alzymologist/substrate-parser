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
//! provided `&[u8]` data must be used in decoding with no data remaining
//! unparsed.
//!
//! For decoding either the entry type (such as the type of particular storage
//! item) or the data internal structure used to find the entry type in metadata
//! (as is the case for signable transactions) must be known.
//!
//! Entry type gets resolved into constituting types with metadata in-built
//! types registry and appropriate `&[u8]` chunks are selected from input blob
//! and decoded. The process follows what the `decode` from the
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
//! a one of balance-displaying [pallets](crate::cards::PALLETS_BALANCE_VALID)
//! or in extensions.
//!
//! # Examples
//!```
//! #[cfg(feature = "std")]
//! {
//! use frame_metadata::RuntimeMetadataV14;
//! use parity_scale_codec::Decode;
//! use primitive_types::H256;
//! use scale_info::{IntoPortable, Path, Registry};
//! use sp_core::crypto::AccountId32;
//! use sp_runtime::generic::Era;
//! use std::str::FromStr;
//! use substrate_parser::{
//!     parse_transaction,
//!     MetaInput,
//!     cards::{
//!         Call, ExtendedData, FieldData, Info,
//!         PalletSpecificData, ParsedData, VariantData,
//!     },
//!     special_indicators::SpecialtyPrimitive,
//! };
//!
//! // A simple signable transaction: Alice sends some cash by `transfer_keep_alive` method
//! let mut signable_data = hex::decode("9c0403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480284d717d5031504025a62029723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e98a8ee9e389043cd8a9954b254d822d34138b9ae97d3b7f50dc6781b13df8d84").unwrap();
//!
//! // Hexadecimal metadata, such as one fetched through rpc query
//! let metadata_westend9111_hex = std::fs::read_to_string("for_tests/westend9111").unwrap();
//!
//! // SCALE-encoded `V14` metadata, first 5 elements cut off here are `META` prefix and
//! // `V14` enum index
//! let metadata_westend9111_vec = hex::decode(&metadata_westend9111_hex.trim()).unwrap()[5..].to_vec();
//!
//! // `RuntimeMetadataV14` decoded and ready to use.
//! let metadata_westend9111 = RuntimeMetadataV14::decode(&mut &metadata_westend9111_vec[..]).unwrap();
//!
//! // Chain genesis hash, typically well-known. Could be fetched through a separate rpc query.
//! let westend_genesis_hash = H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap();
//!
//! let parsed = parse_transaction(
//!     &mut signable_data.clone(),
//!     MetaInput::Raw(metadata_westend9111),
//!     westend_genesis_hash,
//! ).unwrap();
//!
//! let call_data = parsed.call_result.unwrap();
//!
//! // Pallet name.
//! assert_eq!(call_data.0.pallet_name, "Balances");
//!
//! // Call name within the pallet.
//! assert_eq!(call_data.0.variant_name, "transfer_keep_alive");
//!
//! // Call contents are the associated `Field` data.
//! let expected_field_data = vec![
//!     FieldData {
//!         field_name: Some(String::from("dest")),
//!         type_name: Some(String::from("<T::Lookup as StaticLookup>::Source")),
//!         field_docs: String::new(),
//!         data: ExtendedData {
//!             data: ParsedData::Variant(VariantData {
//!                 variant_name: String::from("Id"),
//!                 variant_docs: String::new(),
//!                 fields: vec![
//!                     FieldData {
//!                         field_name: None,
//!                         type_name: Some(String::from("AccountId")),
//!                         field_docs: String::new(),
//!                         data: ExtendedData {
//!                             data: ParsedData::Id(AccountId32::from_str("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").unwrap()),
//!                             info: vec![
//!                                 Info {
//!                                     docs: String::new(),
//!                                     path: Path::from_segments(vec![
//!                                         "sp_core",
//!                                         "crypto",
//!                                         "AccountId32"
//!                                     ])
//!                                        .unwrap()
//!                                        .into_portable(&mut Registry::new()),
//!                                 }
//!                             ]
//!                         }
//!                     }
//!                 ]
//!             }),
//!             info: vec![
//!                 Info {
//!                     docs: String::new(),
//!                     path: Path::from_segments(vec![
//!                         "sp_runtime",
//!                         "multiaddress",
//!                         "MultiAddress"
//!                     ])
//!                        .unwrap()
//!                        .into_portable(&mut Registry::new()),
//!                 }
//!             ],
//!         }
//!     },
//!     FieldData {
//!         field_name: Some(String::from("value")),
//!         type_name: Some(String::from("T::Balance")),
//!         field_docs: String::new(),
//!         data: ExtendedData {
//!             data: ParsedData::PrimitiveU128{
//!                 value: 100000000,
//!                 specialty: SpecialtyPrimitive::Balance,
//!             },
//!             info: Vec::new()
//!         }
//!     }
//! ];
//! assert_eq!(call_data.0.fields, expected_field_data);
//!
//! // Parsed extensions. Note that many extensions are empty.
//! let expected_extensions_data = vec![
//!     ExtendedData {
//!         data: ParsedData::Composite(Vec::new()),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                     "frame_system",
//!                     "extensions",
//!                     "check_spec_version",
//!                     "CheckSpecVersion",
//!                 ])
//!                     .unwrap()
//!                     .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::Composite(Vec::new()),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                     "frame_system",
//!                     "extensions",
//!                     "check_tx_version",
//!                     "CheckTxVersion",
//!                 ])
//!                     .unwrap()
//!                     .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::Composite(Vec::new()),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                     "frame_system",
//!                     "extensions",
//!                     "check_genesis",
//!                     "CheckGenesis",
//!                 ])
//!                     .unwrap()
//!                     .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::Composite(vec![
//!             FieldData {
//!                 field_name: None,
//!                 type_name: Some(String::from("Era")),
//!                 field_docs: String::new(),
//!                 data: ExtendedData {
//!                     info: vec![
//!                         Info {
//!                             docs: String::new(),
//!                             path: Path::from_segments(vec![
//!                                 "sp_runtime",
//!                                 "generic",
//!                                 "era",
//!                                 "Era",
//!                             ])
//!                             .unwrap()
//!                             .into_portable(&mut Registry::new()),
//!                         }
//!                     ],
//!                     data: ParsedData::Era(Era::Mortal(64, 61)),
//!                 }
//!             }
//!         ]),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                     "frame_system",
//!                     "extensions",
//!                     "check_mortality",
//!                     "CheckMortality",
//!                 ])
//!                     .unwrap()
//!                     .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::Composite(vec![
//!             FieldData {
//!                 field_name: None,
//!                 type_name: Some(String::from("T::Index")),
//!                 field_docs: String::new(),
//!                 data: ExtendedData {
//!                     data: ParsedData::PrimitiveU32 {
//!                         value: 261,
//!                         specialty: SpecialtyPrimitive::Nonce,
//!                     },
//!                     info: Vec::new()
//!                 }
//!             }
//!         ]),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                     "frame_system",
//!                     "extensions",
//!                     "check_nonce",
//!                     "CheckNonce",
//!                 ])
//!                     .unwrap()
//!                     .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::Composite(Vec::new()),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                     "frame_system",
//!                     "extensions",
//!                     "check_weight",
//!                     "CheckWeight",
//!                 ])
//!                     .unwrap()
//!                     .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::Composite(vec![
//!             FieldData {
//!                 field_name: None,
//!                 type_name: Some(String::from("BalanceOf<T>")),
//!                 field_docs: String::new(),
//!                 data: ExtendedData {
//!                     data: ParsedData::PrimitiveU128 {
//!                         value: 10000000,
//!                         specialty: SpecialtyPrimitive::Tip
//!                     },
//!                     info: Vec::new()
//!                 }
//!             }
//!         ]),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                     "pallet_transaction_payment",
//!                     "ChargeTransactionPayment",
//!                 ])
//!                     .unwrap()
//!                     .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::PrimitiveU32 {
//!             value: 9111,
//!             specialty: SpecialtyPrimitive::SpecVersion
//!         },
//!         info: Vec::new()
//!     },
//!     ExtendedData {
//!         data: ParsedData::PrimitiveU32 {
//!             value: 7,
//!             specialty: SpecialtyPrimitive::TxVersion
//!         },
//!         info: Vec::new()
//!     },
//!     ExtendedData {
//!         data: ParsedData::GenesisHash(H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap()),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                    "primitive_types",
//!                    "H256",
//!                ])
//!                    .unwrap()
//!                    .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::BlockHash(H256::from_str("98a8ee9e389043cd8a9954b254d822d34138b9ae97d3b7f50dc6781b13df8d84").unwrap()),
//!         info: vec![
//!             Info {
//!                 docs: String::new(),
//!                 path: Path::from_segments(vec![
//!                    "primitive_types",
//!                    "H256",
//!                ])
//!                    .unwrap()
//!                    .into_portable(&mut Registry::new()),
//!             }
//!         ]
//!     },
//!     ExtendedData {
//!         data: ParsedData::Tuple(Vec::new()),
//!         info: Vec::new()
//!     },
//!     ExtendedData {
//!         data: ParsedData::Tuple(Vec::new()),
//!         info: Vec::new()
//!     },
//!     ExtendedData {
//!         data: ParsedData::Tuple(Vec::new()),
//!         info: Vec::new()
//!     }
//! ];
//!
//!  assert_eq!(parsed.extensions, expected_extensions_data);
//! }
//! ```
//!
//! Parsed data could be transformed into set of flat and formatted
//! [`ExtendedCard`] cards using `card` method.
//!
//! Cards could be printed using `show` or `show_with_docs` methods into
//! readable Strings.
#![no_std]
#![deny(unused_crate_dependencies)]

use primitive_types::H256;
use scale_info::{interner::UntrackedSymbol, PortableRegistry};

#[cfg(not(feature = "std"))]
pub mod additional_types;
pub mod cards;
use cards::{Call, ExtendedCard, ExtendedData};
pub mod compacts;
use compacts::get_compact;
mod decoding_sci;
pub use decoding_sci::decode_as_call;
use decoding_sci::{decode_with_type, Ty};
mod decoding_sci_ext;
pub use decoding_sci_ext::decode_extensions;
pub mod error;
use error::{ParserError, SignableError};
mod metadata_check;
pub use metadata_check::{CheckedMetadata, MetaInput};
pub mod printing_balance;
mod propagated;
use propagated::Propagated;
pub mod special_indicators;
mod special_types;
pub mod storage_data;

#[cfg(feature = "std")]
#[cfg(test)]
mod tests;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc as std;

use crate::std::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::any::TypeId;

#[cfg(not(feature = "std"))]
use core::any::TypeId;

/// Chain data necessary to display decoded data correctly.
///
/// `ShortSpecs` are not checked in this crate to be correct ones for the chain,
/// this must be done elsewhere.
///
/// Using wrong specs may result in incorrectly displayed parsed information.
pub struct ShortSpecs {
    pub base58prefix: u16,
    pub decimals: u8,
    pub name: String,
    pub unit: String,
}

/// Marked signable transaction data, with associated start positions for call
/// and extensions data.
pub struct MarkedData<'a> {
    data: &'a [u8],
    call_start: usize,
    extensions_start: usize,
}

impl<'a> MarkedData<'a> {
    /// Make `MarkedData` from a signable transaction data slice.
    pub fn mark(data: &'a [u8]) -> Result<Self, SignableError> {
        let mut call_start: usize = 0;
        let call_length = get_compact::<u32>(data, &mut call_start)
            .map_err(|_| SignableError::CutSignable)? as usize;
        let extensions_start = call_start + call_length;
        match data.get(call_start..extensions_start) {
            Some(_) => Ok(Self {
                data,
                call_start,
                extensions_start,
            }),
            None => Err(SignableError::CutSignable),
        }
    }

    /// Whole signable transaction data.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Signable transaction data with extensions data cut off.
    ///
    /// Positions in resulting slice exactly match the positions in original
    /// input.
    ///
    /// Extensions are cut to ensure the call decoding never gets outside the
    /// call data.
    pub(crate) fn data_no_extensions(&self) -> &[u8] {
        &self.data[..self.extensions_start()]
    }

    /// Start positions for call data.
    pub fn call_start(&self) -> usize {
        self.call_start
    }

    /// Start positions for extensions data.
    pub fn extensions_start(&self) -> usize {
        self.extensions_start
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

/// Signable transaction parsing outcome represented as formatted flat cards.
#[derive(Debug)]
pub struct TransactionCarded {
    pub call_result: Result<Vec<ExtendedCard>, SignableError>,
    pub extensions: Vec<ExtendedCard>,
}

impl TransactionParsed {
    /// Transform nested data from `TransactionParsed` into flat cards.
    pub fn card(self, short_specs: &ShortSpecs) -> TransactionCarded {
        let start_indent = 0;
        let mut extensions: Vec<ExtendedCard> = Vec::new();
        for ext in self.extensions.iter() {
            let addition_set = ext.card(start_indent, true, short_specs);
            if !addition_set.is_empty() {
                extensions.extend_from_slice(&addition_set)
            }
        }
        TransactionCarded {
            call_result: self
                .call_result
                .map(|call| call.card(start_indent, short_specs)),
            extensions,
        }
    }
}

/// Parse a signable transaction.
pub fn parse_transaction(
    data: &[u8],
    meta_input: MetaInput,
    genesis_hash: H256,
) -> Result<TransactionParsed, SignableError> {
    let checked_metadata = meta_input.checked().map_err(SignableError::MetaVersion)?;

    // unable to separate call date and extensions,
    // some fundamental flaw is in transaction itself
    let marked_data = MarkedData::mark(data)?;

    // try parsing extensions, check that spec version and genesis hash are
    // correct
    let extensions = decode_extensions(&marked_data, &checked_metadata, genesis_hash)?;

    // try parsing call data
    let call_result = decode_as_call(&marked_data, &checked_metadata.meta_v14);

    Ok(TransactionParsed {
        call_result,
        extensions,
    })
}

/// Decode part of `&[u8]` slice as a known type using `V14` metadata.
///
/// Input `position` marks the first element in data that goes into the
/// decoding. As decoding proceeds, `position` gets changed.
///
/// Some data may remain undecoded here.
///
/// [`decode_all_as_type`] is suggested instead if all input is expected to be
/// used.
pub fn decode_as_type_at_position(
    ty_symbol: &UntrackedSymbol<TypeId>,
    data: &[u8],
    registry: &PortableRegistry,
    position: &mut usize,
) -> Result<ExtendedData, ParserError> {
    decode_with_type(
        &Ty::Symbol(ty_symbol),
        data,
        position,
        registry,
        Propagated::new(),
    )
}

/// Decode whole `&[u8]` slice as a known type using `V14` metadata.
///
/// All data is expected to be used for the decoding.
pub fn decode_all_as_type(
    ty_symbol: &UntrackedSymbol<TypeId>,
    data: &[u8],
    registry: &PortableRegistry,
) -> Result<ExtendedData, ParserError> {
    let mut position: usize = 0;
    let out = decode_as_type_at_position(ty_symbol, data, registry, &mut position)?;
    if position != data.len() {
        Err(ParserError::SomeDataNotUsedBlob { from: position })
    } else {
        Ok(out)
    }
}
