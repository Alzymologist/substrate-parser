use frame_metadata::v14::{RuntimeMetadataV14, StorageEntryMetadata};
use parity_scale_codec::Decode;
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, IntoPortable, Path, Registry, TypeDef,
};
use sp_core::{twox_128, H256};
use std::str::FromStr;

use crate::cards::{
    ExtendedData, FieldData, Info, ParsedData, Sequence, SequenceData, SequenceRawData, VariantData,
};
use crate::error::{ParserError, SignableError};
use crate::special_indicators::SpecialtyPrimitive;
use crate::storage_data::{decode_as_storage_entry, KeyData, KeyPart};
use crate::{decode_blob_as_type, parse_transaction, MetaInput, ShortSpecs};

fn metadata(filename: &str) -> RuntimeMetadataV14 {
    let metadata_hex = std::fs::read_to_string(&filename).unwrap();
    let metadata_vec = hex::decode(&metadata_hex.trim()).unwrap()[5..].to_vec();
    RuntimeMetadataV14::decode(&mut &metadata_vec[..]).unwrap()
}

fn specs() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 42,
        decimals: 12,
        name: "westend".to_string(),
        unit: "WND".to_string(),
    }
}

fn system_digest_ty(meta_v14: &RuntimeMetadataV14) -> UntrackedSymbol<std::any::TypeId> {
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
    let data = hex::decode("4d0210020806000046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a07001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d550008009723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();
    let reply = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap()
    .card(&specs());

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
Network: westend9111
Tx Version: 7
Block Hash: 5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_2() {
    let data = hex::decode("4d0210020806000046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a07001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d550008009723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();
    let reply = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap()
    .card(&specs());

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
    let data = hex::decode("9c0403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480284d717d5031504025a62029723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e98a8ee9e389043cd8a9954b254d822d34138b9ae97d3b7f50dc6781b13df8d84").unwrap();
    let reply = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap()
    .card(&specs());

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
Network: westend9111
Tx Version: 7
Block Hash: 98a8ee9e389043cd8a9954b254d822d34138b9ae97d3b7f50dc6781b13df8d84
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_4() {
    let data = hex::decode("2509000115094c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f726520657420646f6c6f7265206d61676e6120616c697175612e20436f6e67756520657520636f6e7365717561742061632066656c697320646f6e65632e20547572706973206567657374617320696e7465676572206567657420616c6971756574206e696268207072616573656e742e204e6571756520636f6e76616c6c6973206120637261732073656d70657220617563746f72206e657175652e204e65747573206574206d616c6573756164612066616d6573206163207475727069732065676573746173207365642074656d7075732e2050656c6c656e746573717565206861626974616e74206d6f726269207472697374697175652073656e6563747573206574206e657475732065742e205072657469756d2076756c7075746174652073617069656e206e656320736167697474697320616c697175616d2e20436f6e76616c6c69732061656e65616e20657420746f72746f7220617420726973757320766976657272612e20566976616d757320617263752066656c697320626962656e64756d207574207472697374697175652065742065676573746173207175697320697073756d2e204d616c6573756164612070726f696e206c696265726f206e756e6320636f6e73657175617420696e74657264756d207661726975732e2045022c009723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e1b2b0a177ad4f3f93f9a56dae700e938a40201a5beabbda160a74c70e612c66a").unwrap();
    let reply = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap()
    .card(&specs());

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
Network: westend9111
Tx Version: 7
Block Hash: 1b2b0a177ad4f3f93f9a56dae700e938a40201a5beabbda160a74c70e612c66a
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn tr_5() {
    let data = hex::decode("a80a0000dc621b10081b4b51335553ef8df227feb0327649d00beab6e09c10a1dce973590b00407a10f35a24010000dc07000001000000fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c5cfeb3e46c080274613bdb80809a3e84fe782ac31ea91e2c778de996f738e620").unwrap();
    let specs_acala = ShortSpecs {
        base58prefix: 10,
        decimals: 12,
        name: "acala".to_string(),
        unit: "ACA".to_string(),
    };
    let reply = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/acala2012")),
        H256::from_str("fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c").unwrap(),
    )
    .unwrap()
    .card(&specs_acala);

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
Network: acala2012
Tx Version: 1
Block Hash: 5cfeb3e46c080274613bdb80809a3e84fe782ac31ea91e2c778de996f738e620
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn storage_1_good() {
    // This value is `Digest` fetched from westmint storage at some point.
    let data = hex::decode("04066175726120c1f2410800000000").unwrap();

    // Correct westmint metadata.
    let metadata = metadata("for_tests/westmint9270");

    // Type associated with `Digest` storage entry in `System` pallet.
    let system_digest_ty = system_digest_ty(&metadata);

    // `Digest` type is `11` in types registry.
    assert!(system_digest_ty.id() == 11);

    // It is a composite with a single field.
    // Here in good metadata `westmint9270` the field type identifier is `12`
    // and further type resolving is possible.
    let metadata_type_11 = metadata.types.resolve(11).unwrap();
    if let TypeDef::Composite(x) = metadata_type_11.type_def() {
        assert!(x.fields()[0].ty().id() == 12);
    } else {
        panic!("Expected composite.")
    }

    let reply = decode_blob_as_type(&system_digest_ty, &data, &metadata.types).unwrap();
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
    let metadata = metadata("for_tests/westmint9270_spoiled_digest");

    // Type associated with `Digest` storage entry in `System` pallet.
    let system_digest_ty = system_digest_ty(&metadata);

    // `Digest` type is `11` in types registry.
    assert!(system_digest_ty.id() == 11);

    // In good metadata `westmint9270` the field type identifier was `12` (see
    // the `storage_1_good` test above), and further type resolving was
    // possible.
    // Here, in spoiled metadata `westmint9270_spoiled_digest` the field type
    // identifier was manually swapped to `11` and thus could cause endless type
    // resolution cycle.
    // This check is to make sure the metadata really contains error in type
    // referencing.
    let metadata_type_11 = metadata.types.resolve(11).unwrap();
    if let TypeDef::Composite(x) = metadata_type_11.type_def() {
        assert!(x.fields()[0].ty().id() == 11);
    } else {
        panic!("Expected composite.")
    }

    let reply = decode_blob_as_type(&system_digest_ty, &data, &metadata.types).unwrap_err();
    let reply_known = ParserError::CyclicMetadata(11);
    assert_eq!(reply_known, reply);
}

#[test]
fn storage_3_assets_with_key() {
    // The key and the value correspond to one of the westmint storage entries
    // in `Assets` pallet `Metadata` storage.
    let hex_key = "0x682a59d51ab9e48a8c8cc418ff9708d2b5f3822e35ca2f31ce3526eab1363fd211d2df4e979aa105cf552e9544ebd2b500000000";

    // Cut off the prefix from the key.
    let key = hex::decode(hex_key.trim_start_matches(&format!(
        "0x{}{}",
        hex::encode(twox_128(b"Assets")),
        hex::encode(twox_128(b"Metadata"))
    )))
    .unwrap();

    let value = hex::decode(
        "c07a64621700000000000000000000003c4f70656e5371756172652054657374104f534e540a00",
    )
    .unwrap();

    // Westmint metadata.
    let metadata = metadata("for_tests/westmint9270");

    // `StorageEntryMetadata` for `Assets` pallet, `Metadata` entry.
    let storage_entry_metadata = assets_metadata_storage_entry(&metadata);

    let storage =
        decode_as_storage_entry(&key, &value, storage_entry_metadata, &metadata.types).unwrap();

    // Parsed key.
    let expected_key_data = KeyData::SingleHash {
        content: KeyPart::Parsed(ExtendedData {
            data: ParsedData::PrimitiveU32 {
                value: 0,
                specialty: SpecialtyPrimitive::None,
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
                        specialty: SpecialtyPrimitive::Balance,
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
                        specialty: SpecialtyPrimitive::None,
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
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
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
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap();
    let call_error = parsed.call_result.unwrap_err();
    let call_error_known = SignableError::SomeDataNotUsedCall{from: 26, to: 42};
    assert_eq!(call_error_known, call_error);
}

#[test]
fn parser_error3() {
    let data = hex::decode("a40403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f3300").unwrap();
    let signable_error = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap_err();
    let signable_error_known = SignableError::SomeDataNotUsedExtensions{from: 118};
    assert_eq!(signable_error_known, signable_error);
}

#[test]
fn parser_error_4() {
    let data = hex::decode("a40403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a481700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f33").unwrap();
    let parsed = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap();
    let call_error = parsed.call_result.unwrap_err();
    let call_error_known = SignableError::Parsing(ParserError::NoCompact{position: 36});
    assert_eq!(call_error_known, call_error);
}

#[test]
fn parser_error_5() {
    let data = hex::decode("a40403068eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f33").unwrap();
    let parsed = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap();
    let call_error = parsed.call_result.unwrap_err();
    let call_error_known = SignableError::Parsing(ParserError::UnexpectedEnumVariant{position: 3});
    assert_eq!(call_error_known, call_error);
}

#[test]
fn parser_error_6() {
    let data = hex::decode("a40403028eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e8764817b501b8009723000005000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e538a7d7a0ac17eb6dd004578cb8e238c384a10f57c999a3fa1200409cd9b3f33").unwrap();
    let parsed = parse_transaction(
        &data,
        MetaInput::Raw(&metadata("for_tests/westend9111")),
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap(),
    )
    .unwrap();
    let call_error = parsed.call_result.unwrap_err();
    let call_error_known = SignableError::Parsing(ParserError::DataTooShort);
    assert_eq!(call_error_known, call_error);
}
