//! This crate is a parser for Substrate chain data. It could be used to
//! decode signable transactions, calls, events, storage items etc. with chain
//! metadata. Decoded data could be pattern matched or represented in readable
//! form.
//!
//! Key trait [`AsMetadata`] describes the metadata suitable for parsing of
//! signable transactions and other encoded chain items, for example, the data
//! from chain storage. Trait [`AsCompleteMetadata`] is [`AsMetadata`] with few
//! additional properties, it describes the metadata suitable for parsing of
//! unchecked extrinsics.
//!
//! Traits `AsMetadata` and `AsCompleteMetadata` could be applied as well to
//! metadata addressable in external memory. As metadata typically is typically
//! a few hundred kB, this is useful for hardware devices with limited memory
//! capacity.
//!
//! `AsMetadata` and `AsCompleteMetadata` are implemented for `RuntimeMetadata`
//! versions `V14` and `V15`, both of which have conveniently in-built types
//! registry allowing to track types using metadata itself without any
//! additional information.
//!
//! # Assumptions
//!
//! Chain data is [SCALE-encoded](https://docs.substrate.io/reference/scale-codec/).
//! Data blobs entering decoder are expected to be decoded completely: all
//! provided bytes must be used in decoding with no data remaining unparsed.
//!
//! For decoding either the entry type (such as the type of particular storage
//! item) or the data internal structure used to find the entry type in metadata
//! (as is the case for signable transactions or unchecked extrinsics) must be
//! known.
//!
//! Entry type gets resolved into constituting types with metadata in-built
//! types registry and appropriate bytes chunks are selected from input blob
//! and decoded. The process follows what the `decode` from the
//! [SCALE codec](parity_scale_codec) does, except the types that go into the
//! decoder are found dynamically during the decoding itself.
//!
//! ## Signable transactions
//!
//! Signable transaction consist of the call part and extensions part.
//!
//! Call part may or may not be double SCALE-encoded, i.e. SCALE-encoded call
//! data may or may not be preceded by [compact](parity_scale_codec::Compact) of
//! the encoded call length.
//!
//! Function [`parse_transaction`] is used for signable transactions with double
//! SCALE-encoded call data. Call length allows to separate encoded call data
//! and extensions, and decode them independently, extensions first. This
//! approach is preferable if multiple metadata entries (same chain, different
//! `spec_version`) are tried for transaction parsing, because extensions must
//! contain metadata `spec_version`, thus allowing to check if the correct one
//! is being used for decoding before call decoding even starts.
//!
//! Signable transactions without length prefix are parsed with function
//! [`parse_transaction_unmarked`], call first. Similarly, found in extensions
//! chain `spec_version` is checked to assure the correct metadata was used.
//!
//! Call parsing entry point is `call_ty`. This is the type describing all calls
//! available on chain. Effectively, `call_ty` leads to enum with variants
//! corresponsing to all pallets, first `u8` of the data is the pallet index.
//! Each variant is expected to have only one field, the type of which is also
//! an enum. This second enum represents all calls available in the selected
//! pallet, with second `u8` of the data being enum variant index, i.e. exact
//! call contained in transaction. Further data is just the set of fields for
//! this selected variant.
//!
//! Remaining data is SCALE-encoded set of signable extensions, as declared, for
//! example, in
//! [`v14::ExtrinsicMetadata`](frame_metadata::v14::ExtrinsicMetadata) for `V14`
//! and in [`v15::ExtrinsicMetadata`](frame_metadata::v15::ExtrinsicMetadata)
//! for `V15`. Chain genesis hash must be found among the decoded extensions and
//! must match the genesis hash known for the chain, if the one was provided for
//! parser. `spec_version` must be found among the decoded extensions and must
//! match the `spec_version` derived from the provided metadata.
//!
//! ## Storage items
//!
//! Storage items could be queried from chain via rpc calls, and the retrieved
//! SCALE-encoded data has a type declared in corresponding chain metadata
//! [`StorageEntryType`](frame_metadata::v14::StorageEntryType).
//!
//! Storage items (combination of both a key and a value) is parsed using
//! [`decode_as_storage_entry`] function.
//!
//! ## Unchecked extrinsics
//!
//! Unchecked extrinsics could be decoded with metadata implementing
//! [`AsCompleteMetadata`] trait, using function
//! [`decode_as_unchecked_extrinsic`].
//!
//! ## Other items
//!
//! Any part of a bytes blob could be decoded if the corresponding type is known
//! using function [`decode_as_type_at_position`].
//!
//! For cases when whole blob corresponds to a single known type, function
//! [`decode_all_as_type`] is suggested.
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
//! `Call` and `Event`. If it does not match, the data is parsed as is, i.e.
//! without fitting into specific item format.
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
//! Some types (`AccountId32`, `Era`, public key types, signature types) are
//! re-defined in this crate (module `additional_types`) similarly to their
//! original counterparts in `sp_core` and `sp_runtime` crates. This is done to
//! ensure `no_std` compatibility and simplify dependencies tree. Internal
//! content of these types could be seamlessly transferred into original types
//! if need be.
//!
//! # Features
//!
//! Crate supports `no_std` in `default-features = false` mode.
//!
//! # Examples
//!```
//! # #[cfg(feature = "std")]
//! # {
//! use frame_metadata::v14::RuntimeMetadataV14;
//! use parity_scale_codec::Decode;
//! use primitive_types::H256;
//! use scale_info::{IntoPortable, Path, Registry};
//! use std::str::FromStr;
//! use substrate_parser::{
//!     parse_transaction,
//!     AddressableBuffer,
//!     AsMetadata,
//!     additional_types::{AccountId32, Era},
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
//!     Some(westend_genesis_hash),
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
//!                             data: ParsedData::Id(AccountId32(hex::decode("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").unwrap().try_into().unwrap())),
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

pub use external_memory_tools::{AddressableBuffer, ExternalMemory};
use parity_scale_codec::{Decode, Encode};
use primitive_types::H256;
use scale_info::interner::UntrackedSymbol;

pub mod additional_types;
pub mod cards;
pub mod compacts;
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
use std::{any::TypeId, marker::PhantomData};

#[cfg(not(feature = "std"))]
use core::{any::TypeId, marker::PhantomData};

pub use decoding_sci::{decode_as_call, decode_as_call_unmarked, ResolvedTy};
pub use decoding_sci_ext::{decode_extensions, decode_extensions_unmarked};
pub use storage_data::decode_as_storage_entry;
pub use traits::{AsCompleteMetadata, AsMetadata, ResolveType};
pub use unchecked_extrinsic::decode_as_unchecked_extrinsic;

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
pub struct MarkedData<'a, B, E, M>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    data: &'a B,
    call_start: usize,
    extensions_start: usize,
    ext_memory_type: PhantomData<E>,
    metadata_type: PhantomData<M>,
}

impl<'a, B, E, M> MarkedData<'a, B, E, M>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    /// Make `MarkedData` from a signable transaction data slice.
    pub fn mark(data: &'a B, ext_memory: &mut E) -> Result<Self, SignableError<E, M>> {
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
                metadata_type: PhantomData,
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
        self.data
            .limit_length(self.extensions_start())
            .expect("checked extensions start to be within limits when generating `MarkedData`")
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
pub struct TransactionParsed<E, M>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    pub call_result: Result<Call, SignableError<E, M>>,
    pub extensions: Vec<ExtendedData>,
}

/// Signable transaction parsing outcome represented as formatted flat cards.
#[derive(Debug)]
pub struct TransactionCarded<E, M>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    pub call_result: Result<Vec<ExtendedCard>, SignableError<E, M>>,
    pub extensions: Vec<ExtendedCard>,
}

impl<E, M> TransactionParsed<E, M>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    /// Transform nested data from `TransactionParsed` into flat cards.
    pub fn card(self, short_specs: &ShortSpecs, spec_name: &str) -> TransactionCarded<E, M> {
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
    metadata: &M,
    optional_genesis_hash: Option<H256>,
) -> Result<TransactionParsed<E, M>, SignableError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    // unable to separate call date and extensions,
    // some fundamental flaw is in transaction itself
    let marked_data = MarkedData::<B, E, M>::mark(data, ext_memory)?;

    // try parsing extensions, check that `spec_version` and genesis hash are
    // correct
    let extensions =
        decode_extensions::<B, E, M>(&marked_data, ext_memory, metadata, optional_genesis_hash)?;

    // try parsing call data
    let call_result = decode_as_call::<B, E, M>(&marked_data, ext_memory, metadata);

    Ok(TransactionParsed::<E, M> {
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

/// Parse a signable transaction when call is not prefixed by call length.
pub fn parse_transaction_unmarked<B, E, M>(
    data: &B,
    ext_memory: &mut E,
    metadata: &M,
    optional_genesis_hash: Option<H256>,
) -> Result<TransactionUnmarkedParsed, SignableError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut position = 0;

    // try parsing call data
    let call = decode_as_call_unmarked::<B, E, M>(data, &mut position, ext_memory, metadata)?;

    // try parsing extensions, check that `spec_version` and genesis hash are
    // correct
    let extensions = decode_extensions_unmarked::<B, E, M>(
        data,
        &mut position,
        ext_memory,
        metadata,
        optional_genesis_hash,
    )?;

    Ok(TransactionUnmarkedParsed { call, extensions })
}

/// Decode part of bytes slice starting at a given position as a known type.
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

/// Decode whole bytes slice as a known type.
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
