#![cfg(feature = "std")]

use frame_metadata::v14::RuntimeMetadataV14;
use parity_scale_codec::{Decode, Encode};
use sp_core::H256;
use std::str::FromStr;
use substrate_parser::{parse_transaction, traits::RuntimeMetadataV14Shortened};

fn main() {
    let meta_hex = std::fs::read_to_string("for_tests/westend9111").unwrap();
    let meta = hex::decode(&mut meta_hex.trim()).unwrap();
    let meta_v14 = RuntimeMetadataV14::decode(&mut &meta[5..]).unwrap();

    // remaining pallets (TODO automate this):
    // - `System`, to have version constant (no other info needed)
    // - entry point pallet (`Balances` in this case)
    let mut selected_pallets = Vec::new();
    let mut balances_pallet = meta_v14.pallets[4].clone();
    balances_pallet.storage = None;
    balances_pallet.event = None;
    balances_pallet.constants.clear();
    balances_pallet.error = None;
    let mut system_pallet = meta_v14.pallets[0].clone();
    system_pallet.storage = None;
    system_pallet.calls = None;
    system_pallet.event = None;
    system_pallet.constants.retain(|p| p.name == "Version");
    system_pallet.error = None;

    selected_pallets.push(balances_pallet);
    selected_pallets.push(system_pallet);

    // remaining types (TODO automate this):
    // - all used in transaction
    // - all used in extensions
    // - type for version constant
    let mut selected_types = meta_v14.types.clone();
    let ty_no_set: Vec<u32> = vec![9, 57, 144, 179, 588, 589, 590, 591, 593, 594, 595];
    let map = selected_types.retain(|ty_id| ty_no_set.contains(&ty_id));

    let mut monster = selected_types.encode();
    monster.extend_from_slice(&selected_pallets.encode());
    monster.extend_from_slice(&meta_v14.extrinsic.encode());
    monster.extend_from_slice(&meta_v14.ty.encode());
    println!("length of new metadata: {}", monster.len());

    // monster is decodeable!
    let monster_meta = RuntimeMetadataV14::decode(&mut &monster[..]).unwrap();

    let meta_shortened = RuntimeMetadataV14Shortened {
        meta_v14: monster_meta,
        map,
    };
    println!(
        "length of new metadata and mandatory map: {}",
        meta_shortened.encode().len()
    );

    let signable_data = hex::decode("9c0403008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480284d717d5031504025a62029723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e98a8ee9e389043cd8a9954b254d822d34138b9ae97d3b7f50dc6781b13df8d84").unwrap();
    let westend_genesis_hash =
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap();
    let parsed = parse_transaction(
        &signable_data.as_ref(),
        &mut (),
        &meta_shortened,
        westend_genesis_hash,
    )
    .unwrap();
    println!("{parsed:?}");
}
