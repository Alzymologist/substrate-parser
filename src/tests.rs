use crate::std::{
    any::TypeId,
    string::{String, ToString},
    vec::Vec,
};
use external_memory_tools::BufferError;
use frame_metadata::{
    v14::{RuntimeMetadataV14, StorageEntryMetadata},
    v15::RuntimeMetadataV15,
};
use parity_scale_codec::Decode;
use primitive_types::H256;
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, IntoPortable, Path, Registry, TypeDef,
};

use crate::additional_types::{AccountId32, Era, SignatureSr25519};
use crate::cards::{
    ExtendedData, FieldData, Info, ParsedData, Sequence, SequenceData, SequenceRawData, VariantData,
};
use crate::error::{ParserError, RegistryError, SignableError};
use crate::special_indicators::SpecialtyUnsignedInteger;
use crate::storage_data::{decode_as_storage_entry, KeyData, KeyPart};
use crate::traits::AsMetadata;
use crate::unchecked_extrinsic::{decode_as_unchecked_extrinsic, UncheckedExtrinsic};
use crate::{decode_all_as_type, parse_transaction, parse_transaction_unmarked, ShortSpecs};

fn metadata_v14(filename: &str) -> RuntimeMetadataV14 {
    let metadata_hex = std::fs::read_to_string(filename).unwrap();
    let metadata_vec = hex::decode(metadata_hex.trim()).unwrap();
    RuntimeMetadataV14::decode(&mut &metadata_vec[5..]).unwrap()
}

fn metadata_v15(filename: &str) -> RuntimeMetadataV15 {
    let metadata_hex = std::fs::read_to_string(filename).unwrap();
    let metadata_vec = hex::decode(metadata_hex.trim()).unwrap();
    RuntimeMetadataV15::decode(&mut &metadata_vec[5..]).unwrap()
}

fn genesis_hash_acala() -> H256 {
    H256(
        hex::decode("fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_astar() -> H256 {
    H256(
        hex::decode("9eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_bifrost() -> H256 {
    H256(
        hex::decode("262e1b2ad728475fd6fe88e62d34c200abe6fd693931ddad144059b1eb884e5b")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_polkadot() -> H256 {
    H256(
        hex::decode("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_westend() -> H256 {
    H256(
        hex::decode("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn specs_acala() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 10,
        decimals: 12,
        unit: "ACA".to_string(),
    }
}

fn specs_astar() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 5,
        decimals: 18,
        unit: "ASTR".to_string(),
    }
}

fn specs_bifrost() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 6,
        decimals: 12,
        unit: "BNC".to_string(),
    }
}

fn specs_polkadot() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 0,
        decimals: 10,
        unit: "DOT".to_string(),
    }
}

fn specs_westend() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 42,
        decimals: 12,
        unit: "WND".to_string(),
    }
}

fn system_digest_ty(meta_v14: &RuntimeMetadataV14) -> UntrackedSymbol<TypeId> {
    let mut ty = None;
    for pallet in meta_v14.pallets.iter() {
        if let Some(ref storage) = pallet.storage {
            if storage.prefix == "System" {
                for storage_entry in storage.entries.iter() {
                    if storage_entry.name == "Digest" {
                        if let frame_metadata::v14::StorageEntryType::Plain(a) = storage_entry.ty {
                            ty = Some(a);
                        }
                        break;
                    }
                }
            }
        }
    }
    ty.unwrap()
}

fn assets_metadata_storage_entry(
    meta_v14: &RuntimeMetadataV14,
) -> &StorageEntryMetadata<PortableForm> {
    let mut storage_entry_metadata = None;
    for pallet in meta_v14.pallets.iter() {
        if let Some(ref storage) = pallet.storage {
            if storage.prefix == "Assets" {
                for storage_entry in storage.entries.iter() {
                    if storage_entry.name == "Metadata" {
                        storage_entry_metadata = Some(storage_entry);
                        break;
                    }
                }
            }
        }
    }
    storage_entry_metadata.unwrap()
}

#[test]
fn tr_1() {
    let metadata_westend = metadata_v14("for_tests/westend9111");

    let data = hex::decode("4d0210020806000046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a07001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d550008009723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_westend,
        Some(genesis_hash_westend()),
    )
    .unwrap()
    .card(
        &specs_westend(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_westend)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Utility
  Call: batch_all
    Field Name: calls
      Sequence: 2 element(s)
        Pallet: Staking
          Call: bond
            Field Name: controller
              Enum
                Enum Variant Name: Id
                  Id: 5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV
            Field Name: value
              Balance: 1.061900000000 WND
            Field Name: payee
              Enum
                Enum Variant Name: Staked
        Pallet: Staking
          Call: nominate
            Field Name: targets
              Sequence: 3 element(s)
                Enum
                  Enum Variant Name: Id
                    Id: 5CFPcUJgYgWryPaV1aYjSbTpbTLu42V32Ytw1L9rfoMAsfGh
                Enum
                  Enum Variant Name: Id
                    Id: 5G1ojzh47Yt8KoYhuAjXpHcazvsoCXe3G8LZchKDvumozJJJ
                Enum
                  Enum Variant Name: Id
                    Id: 5FZoQhgUCmqBxnkHX7jCqThScS2xQWiwiF61msg63CFL3Y8f
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 5, period: 64
Nonce: 2
Tip: 0 pWND
Chain: westend9111
Tx Version: 7
Genesis Hash: e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e
Block Hash: 5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_2() {
    let metadata_westend = metadata_v14("for_tests/westend9111");

    let data = hex::decode("4d0210020806000046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a07001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d550008009723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_westend,
        Some(genesis_hash_westend()),
    )
    .unwrap()
    .card(
        &specs_westend(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_westend)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show_with_docs())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Utility
(docs: Contains one variant per dispatchable that can be called by an extrinsic., path: pallet_utility >> pallet >> Call)
  Call: batch_all
  (docs: Send a batch of dispatch calls and atomically execute them.
The whole transaction will rollback and fail if any of the calls failed.

May be called from any origin.

- `calls`: The calls to be dispatched from the same origin. The number of call must not
  exceed the constant: `batched_calls_limit` (available in constant metadata).

If origin is root then call are dispatch without checking origin filter. (This includes
bypassing `frame_system::Config::BaseCallFilter`).

# <weight>
- Complexity: O(C) where C is the number of calls to be batched.
# </weight>, path: None)
    Field Name: calls
      Sequence: 2 element(s), element info: [(docs: None, path: westend_runtime >> Call)]
        Pallet: Staking
        (docs: Contains one variant per dispatchable that can be called by an extrinsic., path: pallet_staking >> pallet >> pallet >> Call)
          Call: bond
          (docs: Take the origin account as a stash and lock up `value` of its balance. `controller` will
be the account that controls it.

`value` must be more than the `minimum_balance` specified by `T::Currency`.

The dispatch origin for this call must be _Signed_ by the stash account.

Emits `Bonded`.
# <weight>
- Independent of the arguments. Moderate complexity.
- O(1).
- Three extra DB entries.

NOTE: Two of the storage writes (`Self::bonded`, `Self::payee`) are _never_ cleaned
unless the `origin` falls below _existential deposit_ and gets removed as dust.
------------------
# </weight>, path: None)
            Field Name: controller
              Enum
              (docs: None, path: sp_runtime >> multiaddress >> MultiAddress)
                Enum Variant Name: Id
                  Id: 5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV
                  (docs: None, path: sp_core >> crypto >> AccountId32)
            Field Name: value
              Balance: 1.061900000000 WND
            Field Name: payee
              Enum
              (docs: None, path: pallet_staking >> RewardDestination)
                Enum Variant Name: Staked
        Pallet: Staking
        (docs: Contains one variant per dispatchable that can be called by an extrinsic., path: pallet_staking >> pallet >> pallet >> Call)
          Call: nominate
          (docs: Declare the desire to nominate `targets` for the origin controller.

Effects will be felt at the beginning of the next era.

The dispatch origin for this call must be _Signed_ by the controller, not the stash.

# <weight>
- The transaction's complexity is proportional to the size of `targets` (N)
which is capped at CompactAssignments::LIMIT (MAX_NOMINATIONS).
- Both the reads and writes follow a similar pattern.
# </weight>, path: None)
            Field Name: targets
              Sequence: 3 element(s), element info: [(docs: None, path: sp_runtime >> multiaddress >> MultiAddress)]
                Enum
                  Enum Variant Name: Id
                    Id: 5CFPcUJgYgWryPaV1aYjSbTpbTLu42V32Ytw1L9rfoMAsfGh
                    (docs: None, path: sp_core >> crypto >> AccountId32)
                Enum
                  Enum Variant Name: Id
                    Id: 5G1ojzh47Yt8KoYhuAjXpHcazvsoCXe3G8LZchKDvumozJJJ
                    (docs: None, path: sp_core >> crypto >> AccountId32)
                Enum
                  Enum Variant Name: Id
                    Id: 5FZoQhgUCmqBxnkHX7jCqThScS2xQWiwiF61msg63CFL3Y8f
                    (docs: None, path: sp_core >> crypto >> AccountId32)
";
    assert_eq!(call_known, call_printed);
}

#[test]
fn tr_3() {
    let metadata_westend = metadata_v14("for_tests/westend9111");

    let data = hex::decode("9c0403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480284d717d5031504025a62029723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e98a8ee9e389043cd8a9954b254d822d34138b9ae97d3b7f50dc6781b13df8d84").unwrap();

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_westend,
        Some(genesis_hash_westend()),
    )
    .unwrap()
    .card(
        &specs_westend(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_westend)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Balances
  Call: transfer_keep_alive
    Field Name: dest
      Enum
        Enum Variant Name: Id
          Id: 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
    Field Name: value
      Balance: 100.000000 uWND
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Nonce: 261
Tip: 10.000000 uWND
Chain: westend9111
Tx Version: 7
Genesis Hash: e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e
Block Hash: 98a8ee9e389043cd8a9954b254d822d34138b9ae97d3b7f50dc6781b13df8d84
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_4() {
    let metadata_westend = metadata_v14("for_tests/westend9111");

    let data = hex::decode("2509000115094c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f726520657420646f6c6f7265206d61676e6120616c697175612e20436f6e67756520657520636f6e7365717561742061632066656c697320646f6e65632e20547572706973206567657374617320696e7465676572206567657420616c6971756574206e696268207072616573656e742e204e6571756520636f6e76616c6c6973206120637261732073656d70657220617563746f72206e657175652e204e65747573206574206d616c6573756164612066616d6573206163207475727069732065676573746173207365642074656d7075732e2050656c6c656e746573717565206861626974616e74206d6f726269207472697374697175652073656e6563747573206574206e657475732065742e205072657469756d2076756c7075746174652073617069656e206e656320736167697474697320616c697175616d2e20436f6e76616c6c69732061656e65616e20657420746f72746f7220617420726973757320766976657272612e20566976616d757320617263752066656c697320626962656e64756d207574207472697374697175652065742065676573746173207175697320697073756d2e204d616c6573756164612070726f696e206c696265726f206e756e6320636f6e73657175617420696e74657264756d207661726975732e2045022c009723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e1b2b0a177ad4f3f93f9a56dae700e938a40201a5beabbda160a74c70e612c66a").unwrap();

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_westend,
        Some(genesis_hash_westend()),
    )
    .unwrap()
    .card(
        &specs_westend(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_westend)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: System
  Call: remark
    Field Name: remark
      Text: Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Congue eu consequat ac felis donec. Turpis egestas integer eget aliquet nibh praesent. Neque convallis a cras semper auctor neque. Netus et malesuada fames ac turpis egestas sed tempus. Pellentesque habitant morbi tristique senectus et netus et. Pretium vulputate sapien nec sagittis aliquam. Convallis aenean et tortor at risus viverra. Vivamus arcu felis bibendum ut tristique et egestas quis ipsum. Malesuada proin libero nunc consequat interdum varius. 
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 36, period: 64
Nonce: 11
Tip: 0 pWND
Chain: westend9111
Tx Version: 7
Genesis Hash: e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e
Block Hash: 1b2b0a177ad4f3f93f9a56dae700e938a40201a5beabbda160a74c70e612c66a
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_5() {
    let metadata_acala = metadata_v14("for_tests/acala2012");

    let data = hex::decode("a80a0000dc621b10081b4b51335553ef8df227feb0327649d00beab6e09c10a1dce973590b00407a10f35a24010000dc07000001000000fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c5cfeb3e46c080274613bdb80809a3e84fe782ac31ea91e2c778de996f738e620").unwrap();
    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_acala,
        Some(genesis_hash_acala()),
    )
    .unwrap()
    .card(
        &specs_acala(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_acala)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Balances
  Call: transfer
    Field Name: dest
      Enum
        Enum Variant Name: Id
          Id: 25rZGFcFEWz1d81xB98PJN8LQu5cCwjyazAerGkng5NDuk9C
    Field Name: value
      Balance: 100.000000000000 ACA
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 18, period: 32
Nonce: 0
Tip: 0 pACA
Chain: acala2012
Tx Version: 1
Genesis Hash: fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c
Block Hash: 5cfeb3e46c080274613bdb80809a3e84fe782ac31ea91e2c778de996f738e620
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn storage_1_good() {
    // This value is `Digest` fetched from westmint storage at some point.
    let data = hex::decode("04066175726120c1f2410800000000").unwrap();

    // Correct westmint metadata.
    let metadata = metadata_v14("for_tests/westmint9270");

    // Type associated with `Digest` storage entry in `System` pallet.
    let system_digest_ty = system_digest_ty(&metadata);

    // `Digest` type is `11` in types registry.
    assert!(system_digest_ty.id == 11);

    // It is a composite with a single field.
    // Here in good metadata `westmint9270` the field type identifier is `12`
    // and further type resolving is possible.
    let metadata_type_11 = metadata.types.resolve(11).unwrap();
    if let TypeDef::Composite(x) = &metadata_type_11.type_def {
        assert!(x.fields[0].ty.id == 12);
    } else {
        panic!("Expected composite.")
    }

    let reply = decode_all_as_type::<&[u8], (), RuntimeMetadataV14>(
        &system_digest_ty,
        &data.as_ref(),
        &mut (),
        &metadata.types,
    )
    .unwrap();
    let reply_known = ExtendedData {
        data: ParsedData::Composite(vec![FieldData {
            field_name: Some(String::from("logs")),
            type_name: Some(String::from("Vec<DigestItem>")),
            field_docs: String::new(),
            data: ExtendedData {
                data: ParsedData::SequenceRaw(SequenceRawData {
                    element_info: vec![Info {
                        docs: String::new(),
                        path: Path::from_segments(vec![
                            "sp_runtime",
                            "generic",
                            "digest",
                            "DigestItem",
                        ])
                        .unwrap()
                        .into_portable(&mut Registry::new()),
                    }],
                    data: vec![ParsedData::Variant(VariantData {
                        variant_name: String::from("PreRuntime"),
                        variant_docs: String::new(),
                        fields: vec![
                            FieldData {
                                field_name: None,
                                type_name: Some(String::from("ConsensusEngineId")),
                                field_docs: String::new(),
                                data: ExtendedData {
                                    data: ParsedData::Sequence(SequenceData {
                                        element_info: Vec::new(),
                                        data: Sequence::U8(vec![97, 117, 114, 97]),
                                    }),
                                    info: Vec::new(),
                                },
                            },
                            FieldData {
                                field_name: None,
                                type_name: Some(String::from("Vec<u8>")),
                                field_docs: String::new(),
                                data: ExtendedData {
                                    data: ParsedData::Sequence(SequenceData {
                                        element_info: Vec::new(),
                                        data: Sequence::U8(vec![193, 242, 65, 8, 0, 0, 0, 0]),
                                    }),
                                    info: Vec::new(),
                                },
                            },
                        ],
                    })],
                }),
                info: Vec::new(),
            },
        }]),
        info: vec![Info {
            docs: String::new(),
            path: Path::from_segments(vec!["sp_runtime", "generic", "digest", "Digest"])
                .unwrap()
                .into_portable(&mut Registry::new()),
        }],
    };
    assert_eq!(reply_known, reply);
}

#[test]
fn storage_2_spoiled_digest() {
    // This value is `Digest` fetched from westmint storage at some point.
    let data = hex::decode("04066175726120c1f2410800000000").unwrap();

    // Manually spoiled westmint metadata.
    let metadata = metadata_v14("for_tests/westmint9270_spoiled_digest");

    // Type associated with `Digest` storage entry in `System` pallet.
    let system_digest_ty = system_digest_ty(&metadata);

    // `Digest` type is `11` in types registry.
    assert!(system_digest_ty.id == 11);

    // In good metadata `westmint9270` the field type identifier was `12` (see
    // the `storage_1_good` test above), and further type resolving was
    // possible.
    // Here, in spoiled metadata `westmint9270_spoiled_digest` the field type
    // identifier was manually swapped to `11` and thus could cause endless type
    // resolution cycle.
    // This check is to make sure the metadata really contains error in type
    // referencing.
    let metadata_type_11 = metadata.types.resolve(11).unwrap();
    if let TypeDef::Composite(x) = &metadata_type_11.type_def {
        assert!(x.fields[0].ty.id == 11);
    } else {
        panic!("Expected composite.")
    }

    let reply = decode_all_as_type::<&[u8], (), RuntimeMetadataV14>(
        &system_digest_ty,
        &data.as_ref(),
        &mut (),
        &metadata.types,
    )
    .unwrap_err();
    let reply_known = ParserError::Registry(RegistryError::CyclicMetadata { id: 11 });
    assert_eq!(reply_known, reply);
}

#[test]
fn storage_3_assets_with_key() {
    // The key and the value correspond to one of the westmint storage entries
    // in `Assets` pallet `Metadata` storage.
    let key_input = hex::decode("682a59d51ab9e48a8c8cc418ff9708d2b5f3822e35ca2f31ce3526eab1363fd211d2df4e979aa105cf552e9544ebd2b500000000").unwrap();

    let value_input = hex::decode(
        "c07a64621700000000000000000000003c4f70656e5371756172652054657374104f534e540a00",
    )
    .unwrap();

    // Westmint metadata.
    let metadata = metadata_v14("for_tests/westmint9270");

    // `StorageEntryMetadata` for `Assets` pallet, `Metadata` entry.
    let storage_entry_metadata = assets_metadata_storage_entry(&metadata);

    let storage = decode_as_storage_entry::<&[u8], (), RuntimeMetadataV14>(
        &key_input.as_ref(),
        &value_input.as_ref(),
        &mut (),
        storage_entry_metadata,
        &metadata.types,
    )
    .unwrap();

    // Parsed key.
    let expected_key_data = KeyData::SingleHash {
        content: KeyPart::Parsed(ExtendedData {
            data: ParsedData::PrimitiveU32 {
                value: 0,
                specialty: SpecialtyUnsignedInteger::None,
            },
            info: Vec::new(),
        }),
    };
    assert_eq!(storage.key, expected_key_data);

    // Parsed value.
    let expected_value_data = ExtendedData {
        data: ParsedData::Composite(vec![
            FieldData {
                field_name: Some(String::from("deposit")),
                type_name: Some(String::from("DepositBalance")),
                field_docs: String::new(),
                data: ExtendedData {
                    data: ParsedData::PrimitiveU128 {
                        value: 100435000000,
                        specialty: SpecialtyUnsignedInteger::Balance,
                    },
                    info: Vec::new(),
                },
            },
            FieldData {
                field_name: Some(String::from("name")),
                type_name: Some(String::from("BoundedString")),
                field_docs: String::new(),
                data: ExtendedData {
                    data: ParsedData::Composite(vec![FieldData {
                        field_name: None,
                        type_name: Some(String::from("Vec<T>")),
                        field_docs: String::new(),
                        data: ExtendedData {
                            data: ParsedData::Sequence(SequenceData {
                                element_info: Vec::new(),
                                data: Sequence::U8(vec![
                                    79, 112, 101, 110, 83, 113, 117, 97, 114, 101, 32, 84, 101,
                                    115, 116,
                                ]),
                            }),
                            info: Vec::new(),
                        },
                    }]),
                    info: vec![Info {
                        docs: String::new(),
                        path: Path::from_segments(vec![
                            "sp_runtime",
                            "bounded",
                            "bounded_vec",
                            "BoundedVec",
                        ])
                        .unwrap()
                        .into_portable(&mut Registry::new()),
                    }],
                },
            },
            FieldData {
                field_name: Some(String::from("symbol")),
                type_name: Some(String::from("BoundedString")),
                field_docs: String::new(),
                data: ExtendedData {
                    data: ParsedData::Composite(vec![FieldData {
                        field_name: None,
                        type_name: Some(String::from("Vec<T>")),
                        field_docs: String::new(),
                        data: ExtendedData {
                            data: ParsedData::Sequence(SequenceData {
                                element_info: Vec::new(),
                                data: Sequence::U8(vec![79, 83, 78, 84]),
                            }),
                            info: Vec::new(),
                        },
                    }]),
                    info: vec![Info {
                        docs: String::new(),
                        path: Path::from_segments(vec![
                            "sp_runtime",
                            "bounded",
                            "bounded_vec",
                            "BoundedVec",
                        ])
                        .unwrap()
                        .into_portable(&mut Registry::new()),
                    }],
                },
            },
            FieldData {
                field_name: Some(String::from("decimals")),
                type_name: Some(String::from("u8")),
                field_docs: String::new(),
                data: ExtendedData {
                    data: ParsedData::PrimitiveU8 {
                        value: 10,
                        specialty: SpecialtyUnsignedInteger::None,
                    },
                    info: Vec::new(),
                },
            },
            FieldData {
                field_name: Some(String::from("is_frozen")),
                type_name: Some(String::from("bool")),
                field_docs: String::new(),
                data: ExtendedData {
                    data: ParsedData::PrimitiveBool(false),
                    info: Vec::new(),
                },
            },
        ]),
        info: vec![Info {
            docs: String::new(),
            path: Path::from_segments(vec!["pallet_assets", "types", "AssetMetadata"])
                .unwrap()
                .into_portable(&mut Registry::new()),
        }],
    };
    assert_eq!(storage.value, expected_value_data);

    // Collected docs.
    assert_eq!(storage.docs, " Metadata of an asset.");
}

#[test]
fn parser_error_1() {
    let data = hex::decode("4d0210020806000046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a07001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d55000800a023000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();
    let error = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_v14("for_tests/westend9111"),
        Some(genesis_hash_westend()),
    )
    .unwrap_err();
    let error_known = SignableError::WrongSpecVersion {
        as_decoded: String::from("9120"),
        in_metadata: String::from("9111"),
    };
    assert_eq!(error_known, error);
}

#[test]
fn parser_error_2() {
    let data = hex::decode("a40403048eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f33").unwrap();
    let parsed = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_v14("for_tests/westend9111"),
        Some(genesis_hash_westend()),
    )
    .unwrap();
    let call_error = parsed.call_result.unwrap_err();
    let call_error_known = SignableError::SomeDataNotUsedCall { from: 26, to: 42 };
    assert_eq!(call_error_known, call_error);
}

#[test]
fn parser_error3() {
    let data = hex::decode("a40403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f3300").unwrap();
    let signable_error = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_v14("for_tests/westend9111"),
        Some(genesis_hash_westend()),
    )
    .unwrap_err();
    let signable_error_known = SignableError::SomeDataNotUsedExtensions { from: 118 };
    assert_eq!(signable_error_known, signable_error);
}

#[test]
fn parser_error_4() {
    let data = hex::decode("a40403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a481700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f33").unwrap();
    let parsed = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_v14("for_tests/westend9111"),
        Some(genesis_hash_westend()),
    )
    .unwrap();
    let call_error = parsed.call_result.unwrap_err();
    let call_error_known = SignableError::Parsing(ParserError::NoCompact { position: 36 });
    assert_eq!(call_error_known, call_error);
}

#[test]
fn parser_error_5() {
    let data = hex::decode("a40403068eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f33").unwrap();
    let parsed = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_v14("for_tests/westend9111"),
        Some(genesis_hash_westend()),
    )
    .unwrap();
    let call_error = parsed.call_result.unwrap_err();
    let call_error_known =
        SignableError::Parsing(ParserError::UnexpectedEnumVariant { position: 3 });
    assert_eq!(call_error_known, call_error);
}

#[test]
fn parser_error_6() {
    let data = hex::decode("a40403028eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f33").unwrap();
    let parsed = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_v14("for_tests/westend9111"),
        Some(genesis_hash_westend()),
    )
    .unwrap();
    let call_error = parsed.call_result.unwrap_err();

    // `0x02` in position 3 indicates that `Raw` variant of `MultiAddress` is
    // used.
    //
    // `Raw` is `Vec<u8>`, first the shortest compact is found (`0x8eaf0415`,
    //  i.e. `88157155` `u8` elements are expected to be found).  When all call
    // data is exhausted, i.e. after element `42` of the data, no new `u8`
    // element could be found, therefore the error.
    let call_error_known = SignableError::Parsing(ParserError::Buffer(BufferError::DataTooShort {
        position: 42,
        minimal_length: 1,
    }));
    assert_eq!(call_error_known, call_error);
}

#[cfg(feature = "std")]
#[test]
fn unchecked_extrinsic_1() {
    let data = hex::decode("39028400d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d0158e09098782f2e40602b37d94fe3e2d051c2e4927c34bc85525297310642db08280110b4a02b89676e966d07fdf7f362cdeb858d28d681564bd0f7d33dce5c8cc50204000403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480284d717").unwrap();
    let metadata = metadata_v14("for_tests/westend9111");
    let parsed = decode_as_unchecked_extrinsic(&data.as_ref(), &mut (), &metadata).unwrap();
    match parsed {
        UncheckedExtrinsic::Signed {
            address,
            signature,
            extra,
            call,
        } => {
            let expected_address = ExtendedData {
                data: ParsedData::Variant(VariantData {
                    variant_name: "Id".to_string(),
                    variant_docs: "".to_string(),
                    fields: vec![
                        FieldData {
                            field_name: None,
                            type_name: Some("AccountId".to_string()),
                            field_docs: "".to_string(),
                            data: ExtendedData {
                                data: ParsedData::Id(AccountId32(hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d").unwrap().try_into().unwrap())),
                                info: vec![
                                    Info {
                                        docs: "".to_string(),
                                        path: Path::from_segments(vec![
                                            "sp_core",
                                            "crypto",
                                            "AccountId32",
                                        ])
                                        .unwrap()
                                        .into_portable(&mut Registry::new()),
                                    }
                                ]
                            }
                        }
                    ]
                }),
                info: vec![
                    Info {
                        docs: "".to_string(),
                        path: Path::from_segments(vec![
                            "sp_runtime",
                            "multiaddress",
                            "MultiAddress",
                        ])
                        .unwrap()
                        .into_portable(&mut Registry::new()),
                    }
                ]
            };
            assert_eq!(expected_address, address);

            let expected_signature = ExtendedData {
                data: ParsedData::Variant(VariantData {
                    variant_name: "Sr25519".to_string(),
                    variant_docs: "".to_string(),
                    fields: vec![
                        FieldData {
                            field_name: None,
                            type_name: Some("sr25519::Signature".to_string()),
                            field_docs: "".to_string(),
                            data: ExtendedData {
                                data: ParsedData::SignatureSr25519(SignatureSr25519(hex::decode("58e09098782f2e40602b37d94fe3e2d051c2e4927c34bc85525297310642db08280110b4a02b89676e966d07fdf7f362cdeb858d28d681564bd0f7d33dce5c8c").unwrap().try_into().unwrap())),
                                info: vec![
                                    Info {
                                        docs: "".to_string(),
                                        path: Path::from_segments(vec![
                                            "sp_core",
                                            "sr25519",
                                            "Signature",
                                        ])
                                        .unwrap()
                                        .into_portable(&mut Registry::new()),
                                    }
                                ]
                            }
                        }
                    ]
                }),
                info: vec![
                    Info {
                        docs: "".to_string(),
                        path: Path::from_segments(vec![
                            "sp_runtime",
                            "MultiSignature",
                        ])
                        .unwrap()
                        .into_portable(&mut Registry::new()),
                    }
                ]
            };
            assert_eq!(expected_signature, signature);

            let expected_extra = ExtendedData {
                data: ParsedData::Tuple(vec![
                    ExtendedData {
                        data: ParsedData::Composite(vec![]),
                        info: vec![Info {
                            docs: "".to_string(),
                            path: Path::from_segments(vec![
                                "frame_system",
                                "extensions",
                                "check_spec_version",
                                "CheckSpecVersion",
                            ])
                            .unwrap()
                            .into_portable(&mut Registry::new()),
                        }],
                    },
                    ExtendedData {
                        data: ParsedData::Composite(vec![]),
                        info: vec![Info {
                            docs: "".to_string(),
                            path: Path::from_segments(vec![
                                "frame_system",
                                "extensions",
                                "check_tx_version",
                                "CheckTxVersion",
                            ])
                            .unwrap()
                            .into_portable(&mut Registry::new()),
                        }],
                    },
                    ExtendedData {
                        data: ParsedData::Composite(vec![]),
                        info: vec![Info {
                            docs: "".to_string(),
                            path: Path::from_segments(vec![
                                "frame_system",
                                "extensions",
                                "check_genesis",
                                "CheckGenesis",
                            ])
                            .unwrap()
                            .into_portable(&mut Registry::new()),
                        }],
                    },
                    ExtendedData {
                        data: ParsedData::Composite(vec![FieldData {
                            field_name: None,
                            type_name: Some("Era".to_string()),
                            field_docs: "".to_string(),
                            data: ExtendedData {
                                data: ParsedData::Era(Era::Mortal(64, 44)),
                                info: vec![Info {
                                    docs: "".to_string(),
                                    path: Path::from_segments(vec![
                                        "sp_runtime",
                                        "generic",
                                        "era",
                                        "Era",
                                    ])
                                    .unwrap()
                                    .into_portable(&mut Registry::new()),
                                }],
                            },
                        }]),
                        info: vec![Info {
                            docs: "".to_string(),
                            path: Path::from_segments(vec![
                                "frame_system",
                                "extensions",
                                "check_mortality",
                                "CheckMortality",
                            ])
                            .unwrap()
                            .into_portable(&mut Registry::new()),
                        }],
                    },
                    ExtendedData {
                        data: ParsedData::Composite(vec![FieldData {
                            field_name: None,
                            type_name: Some("T::Index".to_string()),
                            field_docs: "".to_string(),
                            data: ExtendedData {
                                data: ParsedData::PrimitiveU32 {
                                    value: 1,
                                    specialty: SpecialtyUnsignedInteger::Nonce,
                                },
                                info: vec![],
                            },
                        }]),
                        info: vec![Info {
                            docs: "".to_string(),
                            path: Path::from_segments(vec![
                                "frame_system",
                                "extensions",
                                "check_nonce",
                                "CheckNonce",
                            ])
                            .unwrap()
                            .into_portable(&mut Registry::new()),
                        }],
                    },
                    ExtendedData {
                        data: ParsedData::Composite(vec![]),
                        info: vec![Info {
                            docs: "".to_string(),
                            path: Path::from_segments(vec![
                                "frame_system",
                                "extensions",
                                "check_weight",
                                "CheckWeight",
                            ])
                            .unwrap()
                            .into_portable(&mut Registry::new()),
                        }],
                    },
                    ExtendedData {
                        data: ParsedData::Composite(vec![FieldData {
                            field_name: None,
                            type_name: Some("BalanceOf<T>".to_string()),
                            field_docs: "".to_string(),
                            data: ExtendedData {
                                data: ParsedData::PrimitiveU128 {
                                    value: 0,
                                    specialty: SpecialtyUnsignedInteger::Tip,
                                },
                                info: vec![],
                            },
                        }]),
                        info: vec![Info {
                            docs: "".to_string(),
                            path: Path::from_segments(vec![
                                "pallet_transaction_payment",
                                "ChargeTransactionPayment",
                            ])
                            .unwrap()
                            .into_portable(&mut Registry::new()),
                        }],
                    },
                ]),
                info: vec![],
            };
            assert_eq!(expected_extra, extra);

            let expected_call_fields = vec![
                FieldData {
                    field_name: Some("dest".to_string()),
                    type_name: Some("<T::Lookup as StaticLookup>::Source".to_string()),
                    field_docs: "".to_string(), 
                    data: ExtendedData {
                            data: ParsedData::Variant(VariantData {
                                variant_name: "Id".to_string(),
                                variant_docs: "".to_string(),
                                fields: vec![
                                    FieldData {
                                        field_name: None,
                                        type_name: Some("AccountId".to_string()),
                                        field_docs: "".to_string(),
                                        data: ExtendedData {
                                            data: ParsedData::Id(AccountId32(hex::decode("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").unwrap().try_into().unwrap())),
                                            info: vec![
                                                Info {
                                                    docs: "".to_string(),
                                                    path: Path::from_segments(vec![
                                                        "sp_core",
                                                        "crypto",
                                                        "AccountId32",
                                                    ])
                                                    .unwrap()
                                                    .into_portable(&mut Registry::new()),
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }),
                            info: vec![
                                Info {
                                    docs: "".to_string(),
                                    path: Path::from_segments(vec![
                                        "sp_runtime",
                                        "multiaddress",
                                        "MultiAddress",
                                    ])
                                    .unwrap()
                                    .into_portable(&mut Registry::new()),
                                }
                            ]
                        }
                    },
                    FieldData {
                        field_name: Some("value".to_string()),
                        type_name: Some("T::Balance".to_string()),
                        field_docs: "".to_string(),
                        data: ExtendedData {
                            data: ParsedData::PrimitiveU128 { value: 100000000, specialty: SpecialtyUnsignedInteger::Balance },
                            info: vec![]
                        }
                    }
                ];
            assert_eq!(expected_call_fields, call.0.fields);
        }
        UncheckedExtrinsic::Unsigned { .. } => panic!("Expected signed extrinsic!"),
    }
}

#[test]
fn tr_7() {
    let data = hex::decode("a00a0304a84b841c4d9d1a179be03bb31131c14ebf6ce22233158139ae28a3dfaac5fe1560a5e9e05cd5038d248ed73e0d9808000003000000fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64cfc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c").unwrap();

    let metadata_acala = metadata_v14("for_tests/acala2200");

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_acala,
        Some(genesis_hash_acala()),
    )
    .unwrap()
    .card(
        &specs_acala(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_acala)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Balances
  Call: transfer_keep_alive
    Field Name: dest
      Enum
        Enum Variant Name: Address20
          Sequence u8: a84b841c4d9d1a179be03bb31131c14ebf6ce222
    Field Name: value
      Balance: 123456789012345.678901234567890123456789 TACA
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Struct: 1 field(s)
  Field Name: nonce
    Nonce: 2339
Tip: 55.555555 uACA
Chain: acala2200
Tx Version: 3
Genesis Hash: fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c
Block Hash: fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_8() {
    let data = hex::decode("641a04100000083434000008383800000c31333200000c313736d503040b63ce64c10c05d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();

    let metadata_polkadot = metadata_v14("for_tests/polkadot9430");

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_polkadot,
        Some(genesis_hash_polkadot()),
    )
    .unwrap()
    .card(
        &specs_polkadot(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_polkadot)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Utility
  Call: force_batch
    Field Name: calls
      Sequence: 4 element(s)
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 44
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 88
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 132
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 176
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Nonce: 1
Tip: 555.2342355555 DOT
Chain: polkadot9430
Tx Version: 24
Genesis Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
Block Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_9() {
    let data = hex::decode("6301039508080401380074063d03aeada02cc26977d0ab68927e12516a3287a3c72cc937981d1e7c9ade0cf91f0300eda947e425ea94b7642cc2d3939d30207e457a92049804580804044e7eca0311ba0594016808003d3d080701ada1020180d1043985798860eb63723790bda41de487e0730251717471e9660ab0aa5a6a65dde70807042c021673020808049d604a87138c0704aa060102ab90ebe5eeaf95088767ace3e78d04147180b016cf193a542fe5c9a4291e70784f6d64fb705349e4a361c453b28d18ba43b8e0bee72dad92845acbe281f21ea6c270f553481dc183b60ca8c1803544f33691adef9c5d4f807827e288143f4af2aa1c2c0b9e6087db1decedb85e2774f792c9bbc61ed85f031d11d175f93ecf7d030800a90307010107d5ebd78dfce4bdb789c0e310e2172b3f3a13ec09e39ba8b644e368816bd7acd57f10030025867d9fc900c0f7afe1ce1fc756f152b3f38e5a010001dec102c8abb0449d91dd617be6a7dc4d7ea0ae7f7cebaf1c9e4c9f0a64716c3d007800000000d50391010b63ce64c10c05d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();

    let metadata_polkadot = metadata_v14("for_tests/polkadot9430");

    let reply = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &metadata_polkadot,
        Some(genesis_hash_polkadot()),
    )
    .unwrap()
    .card(
        &specs_polkadot(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_polkadot)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: XcmPallet
  Call: teleport_assets
    Field Name: dest
      Enum
        Enum Variant Name: V3
          Struct: 2 field(s)
            Field Name: parents
              u8: 149
            Field Name: interior
              Enum
                Enum Variant Name: X8
                  Field Number: 1
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Technical
                        Field Name: part
                          Enum
                            Enum Variant Name: Members
                              Field Name: count
                                u32: 14
                  Field Number: 2
                    Enum
                      Enum Variant Name: Parachain
                        u32: 29
                  Field Number: 3
                    Enum
                      Enum Variant Name: GeneralKey
                        Field Name: length
                          u8: 61
                        Field Name: data
                          Sequence u8: 03aeada02cc26977d0ab68927e12516a3287a3c72cc937981d1e7c9ade0cf91f
                  Field Number: 4
                    Enum
                      Enum Variant Name: AccountKey20
                        Field Name: network
                          Enum
                            Enum Variant Name: None
                        Field Name: key
                          Sequence u8: eda947e425ea94b7642cc2d3939d30207e457a92
                  Field Number: 5
                    Enum
                      Enum Variant Name: PalletInstance
                        u8: 152
                  Field Number: 6
                    Enum
                      Enum Variant Name: PalletInstance
                        u8: 88
                  Field Number: 7
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Technical
                        Field Name: part
                          Enum
                            Enum Variant Name: MoreThanProportion
                              Field Name: nom
                                u32: 15900563
                              Field Name: denom
                                u32: 11908
                  Field Number: 8
                    Enum
                      Enum Variant Name: GeneralIndex
                        u128: 37
    Field Name: beneficiary
      Enum
        Enum Variant Name: V2
          Struct: 2 field(s)
            Field Name: parents
              u8: 104
            Field Name: interior
              Enum
                Enum Variant Name: X8
                  Field Number: 1
                    Enum
                      Enum Variant Name: Parachain
                        u32: 3919
                  Field Number: 2
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Defense
                        Field Name: part
                          Enum
                            Enum Variant Name: Members
                              Field Name: count
                                u32: 10347
                  Field Number: 3
                    Enum
                      Enum Variant Name: AccountIndex64
                        Field Name: network
                          Enum
                            Enum Variant Name: Named
                              Sequence u8: d1043985798860eb63723790bda41de487e0730251717471e9660ab0aa5a6a65
                        Field Name: index
                          u64: 14839
                  Field Number: 4
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Defense
                        Field Name: part
                          Enum
                            Enum Variant Name: MoreThanProportion
                              Field Name: nom
                                u32: 11
                              Field Name: denom
                                u32: 10274176
                  Field Number: 5
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Administration
                        Field Name: part
                          Enum
                            Enum Variant Name: MoreThanProportion
                              Field Name: nom
                                u32: 6183
                              Field Name: denom
                                u32: 587522514
                  Field Number: 6
                    Enum
                      Enum Variant Name: OnlyChild
                  Field Number: 7
                    Enum
                      Enum Variant Name: PalletInstance
                        u8: 170
                  Field Number: 8
                    Enum
                      Enum Variant Name: GeneralKey
                        Sequence u8: ab90ebe5eeaf95088767ace3e78d04147180b016cf193a542fe5c9a4291e70784f6d64fb705349e4a361c453b28d18ba43b8e0bee72dad92845acbe281f21ea6c270f553481dc183b60ca8c1803544f33691adef9c5d4f807827e288143f4af2aa1c2c0b9e6087db1decedb85e2774f792c9bbc61ed85f031d11d175f93ecf7d
    Field Name: assets
      Enum
        Enum Variant Name: V3
          Sequence: 2 element(s)
            Struct: 2 field(s)
              Field Name: id
                Enum
                  Enum Variant Name: Concrete
                    Struct: 2 field(s)
                      Field Name: parents
                        u8: 169
                      Field Name: interior
                        Enum
                          Enum Variant Name: X3
                            Field Number: 1
                              Enum
                                Enum Variant Name: OnlyChild
                            Field Number: 2
                              Enum
                                Enum Variant Name: AccountId32
                                  Field Name: network
                                    Enum
                                      Enum Variant Name: Some
                                        Enum
                                          Enum Variant Name: Ethereum
                                            Field Name: chain_id
                                              u64: 15093
                                  Field Name: id
                                    Sequence u8: d78dfce4bdb789c0e310e2172b3f3a13ec09e39ba8b644e368816bd7acd57f10
                            Field Number: 3
                              Enum
                                Enum Variant Name: AccountKey20
                                  Field Name: network
                                    Enum
                                      Enum Variant Name: None
                                  Field Name: key
                                    Sequence u8: 25867d9fc900c0f7afe1ce1fc756f152b3f38e5a
              Field Name: fun
                Enum
                  Enum Variant Name: NonFungible
                    Enum
                      Enum Variant Name: Undefined
            Struct: 2 field(s)
              Field Name: id
                Enum
                  Enum Variant Name: Abstract
                    Sequence u8: dec102c8abb0449d91dd617be6a7dc4d7ea0ae7f7cebaf1c9e4c9f0a64716c3d
              Field Name: fun
                Enum
                  Enum Variant Name: Fungible
                    u128: 30
    Field Name: fee_asset_item
      u32: 0
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Nonce: 100
Tip: 555.2342355555 DOT
Chain: polkadot9430
Tx Version: 24
Genesis Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
Block Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_10() {
    let data = hex::decode("1f00001b7a61c73f450f4518731981d9cdd99013cfe044294617b74f93ba4bba6090d00b63ce64c10c05d5030403d202964942000000020000009eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c69eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6").unwrap();

    let metadata_astar = metadata_v14("for_tests/astar66");

    let reply = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &metadata_astar,
        Some(genesis_hash_astar()),
    )
    .unwrap()
    .card(
        &specs_astar(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_astar)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Balances
  Call: transfer_allow_death
    Field Name: dest
      Enum
        Enum Variant Name: Id
          Id: WZKwYJmVxzxqF9UbaATqjyYY2859mZEfcTAQEDaXipQYG5w
    Field Name: value
      Balance: 5.552342355555 uASTR
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Nonce: 1
Tip: 1.234567890 nASTR
Chain: astar66
Tx Version: 2
Genesis Hash: 9eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6
Block Hash: 9eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_11() {
    let metadata_polkadot = metadata_v14("for_tests/polkadot9430");

    let data = hex::decode("15000600a9569408db2bf9dd45318e13074b02ffce42dcf91b89cbef0fbe92191eb9627f019b02f1160003792192b533ff24d1ac92297d3905d02aac6dc63c10d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();

    let reply = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &metadata_polkadot,
        Some(genesis_hash_polkadot()),
    )
    .unwrap()
    .card(
        &specs_polkadot(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_polkadot)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Referenda
  Call: submit
    Field Name: proposal_origin
      Enum
        Enum Variant Name: Void
          Enum With No Variants
    Field Name: proposal
      Enum
        Enum Variant Name: Legacy
          Field Name: hash
            H256: a9569408db2bf9dd45318e13074b02ffce42dcf91b89cbef0fbe92191eb9627f
    Field Name: enactment_moment
      Enum
        Enum Variant Name: After
          u32: 384893595
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Immortal
Nonce: 3046252921
Tip: 2158321035032515.9632029318439228220671 TDOT
Chain: polkadot9430
Tx Version: 24
Genesis Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
Block Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_12() {
    let metadata_bifrost = metadata_v14("for_tests/bifrost982");

    let data = hex::decode("78000006000001010000004a6e76f5062e334f7322752db2dae9d19edfe764172aaed603000001000000262e1b2ad728475fd6fe88e62d34c200abe6fd693931ddad144059b1eb884e5bc16d68cf9978c938e405eec35d283be02e720072e8a0f66b11c722bb85d86f01").unwrap();

    let reply = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &metadata_bifrost,
        Some(genesis_hash_bifrost()),
    )
    .unwrap()
    .card(
        &specs_bifrost(),
        &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&metadata_bifrost)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: SystemStaking
  Call: token_config
    Field Name: token
      Enum
        Enum Variant Name: Native
          Enum
            Enum Variant Name: KAR
    Field Name: exec_delay
      Enum
        Enum Variant Name: None
    Field Name: system_stakable_farming_rate
      Enum
        Enum Variant Name: None
    Field Name: add_or_sub
      Enum
        Enum Variant Name: Some
          Bool: true
    Field Name: system_stakable_base
      Enum
        Enum Variant Name: None
    Field Name: farming_poolids
      Enum
        Enum Variant Name: None
    Field Name: lptoken_rates
      Enum
        Enum Variant Name: None
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 1764, period: 2048
Nonce: 193051997
Tip: 231504222224632.337793143774330474361679 TBNC
Chain: bifrost_polkadot982
Tx Version: 1
Genesis Hash: 262e1b2ad728475fd6fe88e62d34c200abe6fd693931ddad144059b1eb884e5b
Block Hash: c16d68cf9978c938e405eec35d283be02e720072e8a0f66b11c722bb85d86f01
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_13() {
    let data = hex::decode("641a04100000083434000008383800000c31333200000c313736d503040b63ce64c10c0541420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();

    let metadata_polkadot = metadata_v15("for_tests/polkadot1000001_v15");

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &metadata_polkadot,
        Some(genesis_hash_polkadot()),
    )
    .unwrap()
    .card(
        &specs_polkadot(),
        &<RuntimeMetadataV15 as AsMetadata<()>>::spec_name_version(&metadata_polkadot)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Utility
  Call: force_batch
    Field Name: calls
      Sequence: 4 element(s)
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 44
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 88
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 132
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 176
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Nonce: 1
Tip: 555.2342355555 DOT
Chain: polkadot1000001
Tx Version: 24
Genesis Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
Block Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
";
    assert_eq!(extensions_known, extensions_printed);
}
