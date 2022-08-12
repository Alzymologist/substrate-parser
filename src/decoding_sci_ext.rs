//! Decode extensions using metadata [`RuntimeMetadataV14`]
//!
use frame_metadata::v14::RuntimeMetadataV14;
/*
use parity_scale_codec::Decode;
use scale_info::{form::PortableForm, Type};
*/
use sp_core::H256;
use sp_runtime::generic::Era;


use crate::cards::{ExtendedData, ParsedData};
use crate::decoding_commons::StLenCheckSpecialtyCompact;
use crate::decoding_sci::decode_with_type;
use crate::error::{ParserDecodingError, ParserError, ParserMetadataError};
use crate::special::{Propagated, SpecialtyPrimitive};


pub fn decode_ext_attempt(
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
    network_version: u32,
    genesis_hash: H256,
) -> Result<Vec<ExtendedData>, ParserError> {
    let mut extensions: Vec<ExtendedData> = Vec::new();
    for signed_extensions_metadata in meta_v14.extrinsic.signed_extensions.iter() {
        extensions.push(decode_with_type(&signed_extensions_metadata.ty, data, meta_v14, Propagated::from_ext_meta(signed_extensions_metadata))?)
    }
    for signed_extensions_metadata in meta_v14.extrinsic.signed_extensions.iter() {
        extensions.push(decode_with_type(&signed_extensions_metadata.additional_signed, data, meta_v14, Propagated::from_ext_meta(signed_extensions_metadata))?)
    }
    if !data.is_empty() {
        return Err(ParserError::Decoding(
            ParserDecodingError::SomeDataNotUsedExtensions,
        ))
    }
    check_extensions(&extensions, network_version, genesis_hash)?;
    Ok(extensions)
}

pub fn check_extensions(extensions: &[ExtendedData], network_version: u32, genesis_hash: H256) -> Result<(), ParserError> {
    let mut collected_ext = CollectedExt::new();
    for ext in extensions.iter() {
        match ext.data {
            ParsedData::Era(era) => collected_ext.add_era(era)?,
            ParsedData::GenesisHash(h) => collected_ext.add_genesis_hash(h)?,
            ParsedData::BlockHash(h) => collected_ext.add_block_hash(h)?,
            ParsedData::PrimitiveU8{value, specialty: SpecialtyPrimitive::SpecVersion} => collected_ext.add_spec_version::<u8>(value)?,
            ParsedData::PrimitiveU16{value, specialty: SpecialtyPrimitive::SpecVersion} => collected_ext.add_spec_version::<u16>(value)?,
            ParsedData::PrimitiveU32{value, specialty: SpecialtyPrimitive::SpecVersion} => collected_ext.add_spec_version::<u32>(value)?,
            ParsedData::PrimitiveU64{value, specialty: SpecialtyPrimitive::SpecVersion} => collected_ext.add_spec_version::<u64>(value)?,
            ParsedData::PrimitiveU128{value, specialty: SpecialtyPrimitive::SpecVersion} => collected_ext.add_spec_version::<u128>(value)?,
            _ => (),
        }
    }
    match collected_ext.spec_version_printed{
        Some(spec_version_found) => {
            if spec_version_found != network_version.to_string() {
                return Err(ParserError::WrongNetworkVersion {
                    as_decoded: spec_version_found,
                    in_metadata: network_version,
                })
            }
        },
        None => return Err(ParserError::FundamentallyBadV14Metadata(
            ParserMetadataError::NoVersionExt,
        )),
    }
    match collected_ext.genesis_hash {
        Some(found_genesis_hash) => {
            if found_genesis_hash != genesis_hash {
                return Err(ParserError::Decoding(
                    ParserDecodingError::GenesisHashMismatch,
                ))
            }
        },
        None => return Err(ParserError::FundamentallyBadV14Metadata(
            ParserMetadataError::NoGenesisHash,
        )),
    }
    if let Some(era) = collected_ext.era {
        if let Era::Immortal = era {
            if let Some(block_hash) = collected_ext.block_hash {
                if genesis_hash != block_hash {
                    return Err(ParserError::Decoding(
                        ParserDecodingError::ImmortalHashMismatch,
                    ))
                }
            }
        }
    }
    Ok(())
}

struct CollectedExt {
    era: Option<Era>,
    genesis_hash: Option<H256>,
    block_hash: Option<H256>,
    spec_version_printed: Option<String>,
}

impl CollectedExt {
    fn new() -> Self {
        Self {
            era: None,
            genesis_hash: None,
            block_hash: None,
            spec_version_printed: None,
        }
    }
    fn add_era(&mut self, era: Era) -> Result<(), ParserError> {
        if self.era.is_some() {Err(ParserError::FundamentallyBadV14Metadata(ParserMetadataError::EraTwice))}
        else {
            self.era = Some(era);
            Ok(())
        }
    }
    fn add_genesis_hash(&mut self, genesis_hash: H256) -> Result<(), ParserError> {
        if self.genesis_hash.is_some() {Err(ParserError::FundamentallyBadV14Metadata(ParserMetadataError::GenesisHashTwice))}
        else {
            self.genesis_hash = Some(genesis_hash);
            Ok(())
        }
    }
    fn add_block_hash(&mut self, block_hash: H256) -> Result<(), ParserError> {
        if self.block_hash.is_some() {Err(ParserError::FundamentallyBadV14Metadata(ParserMetadataError::BlockHashTwice))}
        else {
            self.block_hash = Some(block_hash);
            Ok(())
        }
    }
    fn add_spec_version<T: StLenCheckSpecialtyCompact>(&mut self, spec_version: T) -> Result<(), ParserError> {
        if self.spec_version_printed.is_some() {Err(ParserError::FundamentallyBadV14Metadata(ParserMetadataError::SpecVersionTwice))}
        else {
            self.spec_version_printed = Some(spec_version.to_string());
            Ok(())
        }
    }
}
/*
macro_rules! check {
    ($($id: ident), *) => {
        $(
            impl StLen for $ty {
                fn decode_value(data: &mut Vec<u8>) -> Result<Self, ParserError> {
                    let length = size_of::<Self>();
                    match data.get(..length) {
                        Some(slice_to_decode) => {
                            let out = <Self>::decode(&mut &slice_to_decode[..])
                                .map_err(|_| ParserError::Decoding(ParserDecodingError::PrimitiveFailure(stringify!($ty))))?;
                            *data = data[length..].to_vec();
                            Ok(out)
                        },
                        None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort))
                    }
                }
            }
        )*
    }
}
*/
/*
pub(crate) struct Ext {
    pub(crate) genesis_hash: H256,
    pub(crate) identifier: String,
    pub(crate) specialty: SpecialExt,
    pub(crate) found_ext: FoundExt,
}

impl Ext {
    pub(crate) fn init(genesis_hash: H256) -> Self {
        Self {
            genesis_hash,
            identifier: String::new(),
            specialty: SpecialExt::None,
            found_ext: FoundExt::init(),
        }
    }
    pub(crate) fn check_special(&mut self, current_type: &Type<PortableForm>) {
        self.specialty = match current_type.path().ident() {
            Some(a) => match a.as_str() {
                "Era" => SpecialExt::Era,
                "CheckNonce" => SpecialExt::Nonce,
                "ChargeTransactionPayment" => SpecialExt::Tip,
                _ => SpecialExt::None,
            },
            None => SpecialExt::None,
        };
        if let SpecialExt::None = self.specialty {
            self.specialty = match self.identifier.as_str() {
                "CheckSpecVersion" => SpecialExt::SpecVersion,
                "CheckTxVersion" => SpecialExt::TxVersion,
                "CheckGenesis" => SpecialExt::Hash(Hash::GenesisHash),
                "CheckMortality" => SpecialExt::Hash(Hash::BlockHash),
                "CheckNonce" => SpecialExt::Nonce,
                "ChargeTransactionPayment" => SpecialExt::Tip,
                _ => SpecialExt::None,
            };
        }
    }
}

pub(crate) struct FoundExt {
    pub(crate) era: Option<Era>,
    pub(crate) genesis_hash: Option<H256>,
    pub(crate) block_hash: Option<H256>,
    pub(crate) network_version_printed: Option<String>,
}

impl FoundExt {
    pub(crate) fn init() -> Self {
        Self {
            era: None,
            genesis_hash: None,
            block_hash: None,
            network_version_printed: None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum Hash {
    GenesisHash,
    BlockHash,
}

#[derive(Debug)]
pub(crate) enum SpecialExt {
    Era,
    Nonce,
    Tip,
    SpecVersion,
    TxVersion,
    Hash(Hash),
    None,
}

pub(crate) fn special_case_hash(
    data: &mut Vec<u8>,
    found_ext: &mut FoundExt,
    indent: u32,
    genesis_hash: H256,
    hash: &Hash,
) -> Result<Vec<OutputCard>, ParserError> {
    match data.get(0..32) {
        Some(a) => {
            let decoded_hash = H256::from_slice(a);
            *data = data[32..].to_vec();
            let out = match hash {
                Hash::GenesisHash => {
                    found_ext.genesis_hash = Some(decoded_hash);
                    if decoded_hash != genesis_hash {
                        return Err(ParserError::Decoding(
                            ParserDecodingError::GenesisHashMismatch,
                        ));
                    }
                    Vec::new()
                }
                Hash::BlockHash => {
                    found_ext.block_hash = Some(decoded_hash);
                    vec![OutputCard {
                        card: ParserCard::BlockHash(decoded_hash),
                        indent,
                    }]
                }
            };
            Ok(out)
        }
        None => Err(ParserError::Decoding(ParserDecodingError::DataTooShort)),
    }
}
*/


