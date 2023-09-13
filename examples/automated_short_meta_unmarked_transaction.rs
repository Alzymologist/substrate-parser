#[cfg(feature = "std")]
use frame_metadata::v14::RuntimeMetadataV14;
#[cfg(feature = "std")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "std")]
use sp_core::H256;
#[cfg(feature = "std")]
use std::str::FromStr;
#[cfg(feature = "std")]
use substrate_parser::{
    cut_metadata::{cut_metadata_transaction_unmarked, ShortMetadata},
    parse_transaction_unmarked, ShortSpecs,
};

#[cfg(feature = "std")]
fn main() {
    let meta_file = std::fs::read("for_tests/westend9430").unwrap();
    let meta = Vec::<u8>::decode(&mut &meta_file[..]).unwrap();
    println!("length of basic meta: {}", meta.len());
    let meta_v14 = RuntimeMetadataV14::decode(&mut &meta[5..]).unwrap();

    let specs_westend = ShortSpecs {
        base58prefix: 42,
        decimals: 12,
        unit: "WND".to_string(),
    };

    let data = hex::decode("100208060007001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d55000800d624000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();

    let short_metadata =
        cut_metadata_transaction_unmarked(&data.as_ref(), &mut (), &meta_v14, &specs_westend)
            .unwrap();
    let short_meta_scaled = short_metadata.encode();
    println!("length of shortened meta: {}", short_meta_scaled.len());
    std::fs::write(
        "for_tests/westend9430_short_for_transaction",
        short_meta_scaled,
    )
    .unwrap();

    let meta_shortened_encoded =
        std::fs::read("for_tests/westend9430_short_for_transaction").unwrap();
    let short_metadata = ShortMetadata::decode(&mut &meta_shortened_encoded[..]).unwrap();
    let westend_genesis_hash =
        H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap();
    let parsed = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &short_metadata,
        westend_genesis_hash,
    )
    .unwrap();

    println!("{parsed:?}");
}

#[cfg(not(feature = "std"))]
fn main() {
    panic!("Example is not intended for no-std.");
}
