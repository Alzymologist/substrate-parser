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
//! # Features
//!
//! Crate supports `no_std` in `default-features = false` mode.
//!
//! With feature `std` (available by default) parsed data is translated directly
//! into corresponding Substrate types, such as `Era` from `sp_runtime` and
//! special arrays such as `AccountId32`, public keys, and signatures from
//! `sp_core`.
//!
//! In `no_std` mode types named and built similarly to the original Substrate
//! types are introduced in `additional_types` module, to avoid apparent current
//! incompatibility of `sp_runtime` and `sp_core/full_crypto` with some `no_std`
//! build targets. Types from `additional_types` module are intended mainly for
//! proper parsed data display.
//!
//! Feature `embed-display` is suggested for `no_std` usage, as it supports also
//! base58 representation of `AccountId32` and public keys, identical to the one
//! in `sp_core`.
//!
//! # Examples
//!```
//! #[cfg(feature = "std")]
//! # {
//! use frame_metadata::v14::RuntimeMetadataV14;
//! use parity_scale_codec::Decode;
//! use primitive_types::H256;
//! use scale_info::{IntoPortable, Path, Registry};
//! use sp_core::crypto::AccountId32;
//! use sp_runtime::generic::Era;
//! use std::str::FromStr;
//! use substrate_parser::{
//!     parse_transaction,
//!     AddressableBuffer,
//!     AsMetadata,
//!     cards::{
//!         Call, ExtendedData, FieldData, Info,
//!         PalletSpecificData, ParsedData, VariantData,
//!     },
//!     special_indicators::SpecialtyUnsignedInteger,
//! };
//!
//! // A simple signable transaction: Alice sends some cash by `transfer_keep_alive` method
//! let signable_data = hex::decode("9c0403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480284d717d5031504025a62029723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e98a8ee9e389043cd8a9954b254d822d34138b9ae97d3b7f50dc6781b13df8d84").unwrap();
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
//!     &signable_data.as_ref(),
//!     &mut (),
//!     &metadata_westend9111,
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
//!                 specialty: SpecialtyUnsignedInteger::Balance,
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
//!                 .unwrap()
//!                 .into_portable(&mut Registry::new()),
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
//!                         specialty: SpecialtyUnsignedInteger::Nonce,
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
//!                         specialty: SpecialtyUnsignedInteger::Tip
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
//!             specialty: SpecialtyUnsignedInteger::SpecVersion
//!         },
//!         info: Vec::new()
//!     },
//!     ExtendedData {
//!         data: ParsedData::PrimitiveU32 {
//!             value: 7,
//!             specialty: SpecialtyUnsignedInteger::TxVersion
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
//! # }
//! ```
//!
//! Parsed data could be transformed into set of flat and formatted
//! [`ExtendedCard`] cards using `card` method.
//!
//! Cards could be printed using `show` or `show_with_docs` methods into
//! readable Strings.
#![no_std]
#![deny(unused_crate_dependencies)]

use parity_scale_codec::{Decode, Encode};
use primitive_types::H256;
use scale_info::interner::UntrackedSymbol;

#[cfg(not(feature = "std"))]
pub mod additional_types;
pub mod cards;
pub mod compacts;
pub mod cut_metadata;
pub mod decoding_sci;
mod decoding_sci_ext;
pub mod error;
pub mod printing_balance;
pub mod propagated;
pub mod special_indicators;
mod special_types;
pub mod storage_data;
pub mod traits;
pub mod unchecked_extrinsic;

#[cfg(any(feature = "std", feature = "embed-display"))]
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
use std::{any::TypeId, marker::PhantomData};

#[cfg(not(feature = "std"))]
use core::{any::TypeId, marker::PhantomData};

pub use decoding_sci::{decode_as_call, decode_as_call_unmarked, ResolvedTy};
pub use decoding_sci_ext::{decode_extensions, decode_extensions_unmarked};
pub use traits::{AddressableBuffer, AsMetadata, ExternalMemory, ResolveType};

use cards::{Call, ExtendedCard, ExtendedData};
use compacts::get_compact;
use decoding_sci::{decode_with_type, Ty};
use error::{ParserError, SignableError};
use propagated::Propagated;

/// Chain data necessary to display decoded data correctly.
///
/// `ShortSpecs` are not checked in this crate to be correct ones for the chain,
/// this must be done elsewhere.
///
/// Using wrong specs may result in incorrectly displayed parsed information.
#[derive(Clone, Debug, Decode, Encode)]
pub struct ShortSpecs {
    pub base58prefix: u16,
    pub decimals: u8,
    pub unit: String,
}

/// Marked signable transaction data, with associated start positions for call
/// and extensions data.
pub struct MarkedData<'a, B, E>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
{
    data: &'a B,
    call_start: usize,
    extensions_start: usize,
    ext_memory_type: PhantomData<E>,
}

impl<'a, B, E> MarkedData<'a, B, E>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
{
    /// Make `MarkedData` from a signable transaction data slice.
    pub fn mark(data: &'a B, ext_memory: &mut E) -> Result<Self, SignableError<E>> {
        let mut call_start: usize = 0;
        let call_length = get_compact::<u32, B, E>(data, ext_memory, &mut call_start)
            .map_err(|_| SignableError::CutSignable)? as usize;
        let extensions_start = call_start + call_length;
        match data.read_slice(ext_memory, call_start, call_length) {
            Ok(_) => Ok(Self {
                data,
                call_start,
                extensions_start,
                ext_memory_type: PhantomData,
            }),
            Err(_) => Err(SignableError::CutSignable),
        }
    }

    /// Whole signable transaction data.
    pub fn data(&self) -> &B {
        self.data
    }

    /// Signable transaction data with extensions data cut off.
    ///
    /// Positions in resulting slice exactly match the positions in original
    /// input.
    ///
    /// Extensions are cut to ensure the call decoding never gets outside the
    /// call data.
    pub fn data_no_extensions(&self) -> B {
        self.data.limit_length(self.extensions_start())
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
pub struct TransactionParsed<E: ExternalMemory> {
    pub call_result: Result<Call, SignableError<E>>,
    pub extensions: Vec<ExtendedData>,
}

/// Signable transaction parsing outcome represented as formatted flat cards.
#[derive(Debug)]
pub struct TransactionCarded<E: ExternalMemory> {
    pub call_result: Result<Vec<ExtendedCard>, SignableError<E>>,
    pub extensions: Vec<ExtendedCard>,
}

impl<E: ExternalMemory> TransactionParsed<E> {
    /// Transform nested data from `TransactionParsed` into flat cards.
    pub fn card(self, short_specs: &ShortSpecs, spec_name: &str) -> TransactionCarded<E> {
        let start_indent = 0;
        let mut extensions: Vec<ExtendedCard> = Vec::new();
        for ext in self.extensions.iter() {
            let addition_set = ext.card(start_indent, true, short_specs, spec_name);
            if !addition_set.is_empty() {
                extensions.extend_from_slice(&addition_set)
            }
        }
        TransactionCarded {
            call_result: self
                .call_result
                .map(|call| call.card(start_indent, short_specs, spec_name)),
            extensions,
        }
    }
}

/// Parse a signable transaction.
pub fn parse_transaction<B, E, M>(
    data: &B,
    ext_memory: &mut E,
    meta_v14: &M,
    genesis_hash: H256,
) -> Result<TransactionParsed<E>, SignableError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    // unable to separate call date and extensions,
    // some fundamental flaw is in transaction itself
    let marked_data = MarkedData::<B, E>::mark(data, ext_memory)?;

    // try parsing extensions, check that spec version and genesis hash are
    // correct
    let extensions =
        decode_extensions::<B, E, M>(&marked_data, ext_memory, meta_v14, genesis_hash)?;

    // try parsing call data
    let call_result = decode_as_call::<B, E, M>(&marked_data, ext_memory, meta_v14);

    Ok(TransactionParsed::<E> {
        call_result,
        extensions,
    })
}

/// Signable transaction parsing outcome, for unmarked transaction.
#[derive(Debug)]
pub struct TransactionUnmarkedParsed {
    pub call: Call,
    pub extensions: Vec<ExtendedData>,
}

/// Signable transaction parsing outcome represented as formatted flat cards,
/// for unmarked transaction.
#[derive(Debug)]
pub struct TransactionUnmarkedCarded {
    pub call: Vec<ExtendedCard>,
    pub extensions: Vec<ExtendedCard>,
}

impl TransactionUnmarkedParsed {
    /// Transform nested data from `TransactionUnmarkedParsed` into flat cards.
    pub fn card(self, short_specs: &ShortSpecs, spec_name: &str) -> TransactionUnmarkedCarded {
        let start_indent = 0;
        let mut extensions: Vec<ExtendedCard> = Vec::new();
        for ext in self.extensions.iter() {
            let addition_set = ext.card(start_indent, true, short_specs, spec_name);
            if !addition_set.is_empty() {
                extensions.extend_from_slice(&addition_set)
            }
        }
        TransactionUnmarkedCarded {
            call: self.call.card(start_indent, short_specs, spec_name),
            extensions,
        }
    }
}

/// Parse a signable transaction, Ledger format. Call is not prefixed with call length.
pub fn parse_transaction_unmarked<B, E, M>(
    data: &B,
    ext_memory: &mut E,
    meta_v14: &M,
    genesis_hash: H256,
) -> Result<TransactionUnmarkedParsed, SignableError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut position = 0;

    // try parsing call data
    let call = decode_as_call_unmarked::<B, E, M>(data, &mut position, ext_memory, meta_v14)?;

    // try parsing extensions, check that spec version and genesis hash are
    // correct
    let extensions = decode_extensions_unmarked::<B, E, M>(
        data,
        &mut position,
        ext_memory,
        meta_v14,
        genesis_hash,
    )?;

    Ok(TransactionUnmarkedParsed { call, extensions })
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
pub fn decode_as_type_at_position<B, E, M>(
    ty_symbol: &UntrackedSymbol<TypeId>,
    data: &B,
    ext_memory: &mut E,
    registry: &M::TypeRegistry,
    position: &mut usize,
) -> Result<ExtendedData, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    decode_with_type::<B, E, M>(
        &Ty::Symbol(ty_symbol),
        data,
        ext_memory,
        position,
        registry,
        Propagated::new(),
    )
}

/// Decode whole `&[u8]` slice as a known type using `V14` metadata.
///
/// All data is expected to be used for the decoding.
pub fn decode_all_as_type<B, E, M>(
    ty_symbol: &UntrackedSymbol<TypeId>,
    data: &B,
    ext_memory: &mut E,
    registry: &M::TypeRegistry,
) -> Result<ExtendedData, ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut position: usize = 0;
    let out = decode_as_type_at_position::<B, E, M>(
        ty_symbol,
        data,
        ext_memory,
        registry,
        &mut position,
    )?;
    if position != data.total_len() {
        Err(ParserError::SomeDataNotUsedBlob { from: position })
    } else {
        Ok(out)
    }
}
