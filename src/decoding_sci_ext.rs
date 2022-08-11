//! Decode extensions using metadata [`RuntimeMetadataV14`]
//!
use frame_metadata::v14::RuntimeMetadataV14;
/*
use parity_scale_codec::Decode;
use scale_info::{form::PortableForm, Type};
use sp_core::H256;
use sp_runtime::generic::Era;
*/

use crate::cards::ExtendedData;
use crate::decoding_commons::{SpecialtyPrimitive, SpecialtySet};
use crate::decoding_sci::{decode_with_type, Propagated};
use crate::error::ParserError;


pub fn decode_ext_attempt(
    data: &mut Vec<u8>,
    meta_v14: &RuntimeMetadataV14,
) -> Result<Vec<ExtendedData>, ParserError> {
    let mut out: Vec<ExtendedData> = Vec::new();
    for signed_extensions_metadata in meta_v14.extrinsic.signed_extensions.iter() {
        out.push(decode_with_type(&signed_extensions_metadata.ty, data, meta_v14, Propagated::new_with_specialty_set(extention_specialty_hint(&signed_extensions_metadata.identifier)))?)
    }
    for signed_extensions_metadata in meta_v14.extrinsic.signed_extensions.iter() {
        out.push(decode_with_type(&signed_extensions_metadata.additional_signed, data, meta_v14, Propagated::new_with_specialty_set(extention_specialty_hint(&signed_extensions_metadata.identifier)))?)
    }
    Ok(out)
}

fn extention_specialty_hint(identifier: &str) -> SpecialtySet {
    let specialty_primitive = match identifier {
        "CheckSpecVersion" => SpecialtyPrimitive::SpecVersion,
        "CheckTxVersion" => SpecialtyPrimitive::TxVersion,
//        "CheckGenesis" => SpecialExt::Hash(Hash::GenesisHash),
//        "CheckMortality" => SpecialExt::Hash(Hash::BlockHash),
        "CheckNonce" => SpecialtyPrimitive::Nonce,
        "ChargeTransactionPayment" => SpecialtyPrimitive::Tip,
        _ => SpecialtyPrimitive::None,
    };
    SpecialtySet {
        is_compact: false,
        specialty_primitive,
    }
}

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


