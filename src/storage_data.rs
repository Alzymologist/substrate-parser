use frame_metadata::v14::{StorageEntryMetadata, StorageEntryType, StorageHasher};
use scale_info::{form::PortableForm, interner::UntrackedSymbol, PortableRegistry, TypeDef};
use sp_core::{blake2_128, twox_64};

use crate::cards::{Documented, ExtendedData, Info};
use crate::decode_blob_as_type;
use crate::decoding_sci::{decode_with_type, resolve_ty, Ty};
use crate::error::ParserError;
use crate::propagated::Propagated;

/// Parsed storage data.
#[derive(Debug)]
pub struct Storage {
    /// Storage key data
    pub key: KeyData,

    /// Storage value decoded
    pub value: ExtendedData,

    /// documentation common for all storage entries with the same prefix
    pub docs: String,
}

#[derive(Debug)]
pub enum KeyData {
    None,
    Single { content: KeyPart },
    Tuple { content: Vec<KeyPart>, info: Info },
}

#[derive(Debug)]
pub enum KeyPart {
    Hash(HashData),
    Parsed(ExtendedData),
}

#[derive(Debug)]
pub struct HashData {
    pub hash: Hash,
    pub type_id: u32,
}

/// Hashes from [`StorageHasher`] with no concatenated addition, i.e. with no
/// way to find the hashed value that could be parsed.
#[derive(Debug)]
pub enum Hash {
    Blake2_128([u8; BLAKE2_128_LEN]),
    Blake2_256([u8; BLAKE2_256_LEN]),
    Twox128([u8; TWOX128_LEN]),
    Twox256([u8; TWOX256_LEN]),
}

pub fn decode_as_storage_entry(
    key_trimmed_data: &mut Vec<u8>,
    value_data: &mut Vec<u8>,
    entry_metadata: &StorageEntryMetadata<PortableForm>,
    registry: &PortableRegistry,
) -> Result<Storage, ParserError> {
    let docs = entry_metadata.collect_docs();
    let (key, value) = match &entry_metadata.ty {
        StorageEntryType::Plain(value_ty) => {
            if !key_trimmed_data.is_empty() {
                return Err(ParserError::PlainKeyExceedsPrefix);
            }
            let key = KeyData::None;
            let value = decode_blob_as_type(value_ty, value_data, registry)?;
            (key, value)
        }
        StorageEntryType::Map {
            hashers,
            key: key_ty,
            value: value_ty,
        } => {
            let key = process_key(hashers, key_ty, key_trimmed_data, registry)?;
            let value = decode_blob_as_type(value_ty, value_data, registry)?;
            (key, value)
        }
    };
    Ok(Storage { key, value, docs })
}

pub const BLAKE2_128_LEN: usize = 16;
pub const BLAKE2_256_LEN: usize = 32;
pub const TWOX128_LEN: usize = 16;
pub const TWOX256_LEN: usize = 32;
pub const TWOX64_LEN: usize = 8;

pub fn process_key(
    hashers: &[StorageHasher],
    key_ty: &UntrackedSymbol<std::any::TypeId>,
    key_trimmed_data: &mut Vec<u8>,
    registry: &PortableRegistry,
) -> Result<KeyData, ParserError> {
    // single hash in key
    if hashers.len() == 1 {
        match hashers[0] {
            StorageHasher::Blake2_128 => match key_trimmed_data.get(..BLAKE2_128_LEN) {
                Some(hash_part) => {
                    if key_trimmed_data.len() > BLAKE2_128_LEN {
                        return Err(ParserError::KeyPartsUnused);
                    }
                    Ok(KeyData::Single {
                        content: KeyPart::Hash(HashData {
                            hash: Hash::Blake2_128(
                                hash_part.try_into().expect("stable known length"),
                            ),
                            type_id: key_ty.id(),
                        }),
                    })
                }
                None => Err(ParserError::DataTooShort),
            },
            StorageHasher::Blake2_256 => match key_trimmed_data.get(..BLAKE2_256_LEN) {
                Some(hash_part) => {
                    if key_trimmed_data.len() > BLAKE2_256_LEN {
                        return Err(ParserError::KeyPartsUnused);
                    }
                    Ok(KeyData::Single {
                        content: KeyPart::Hash(HashData {
                            hash: Hash::Blake2_256(
                                hash_part.try_into().expect("stable known length"),
                            ),
                            type_id: key_ty.id(),
                        }),
                    })
                }
                None => Err(ParserError::DataTooShort),
            },
            StorageHasher::Blake2_128Concat => match key_trimmed_data.get(..BLAKE2_128_LEN) {
                Some(hash_part) => {
                    if hash_part != blake2_128(&key_trimmed_data[BLAKE2_128_LEN..]) {
                        return Err(ParserError::KeyPartHashMesmatch);
                    }
                    *key_trimmed_data = key_trimmed_data[BLAKE2_128_LEN..].to_vec();
                    let parsed_key = decode_with_type(
                        &Ty::Symbol(key_ty),
                        key_trimmed_data,
                        registry,
                        Propagated::new(),
                    )?;
                    if !key_trimmed_data.is_empty() {
                        return Err(ParserError::KeyPartsUnused);
                    }
                    Ok(KeyData::Single {
                        content: KeyPart::Parsed(parsed_key),
                    })
                }
                None => Err(ParserError::DataTooShort),
            },
            StorageHasher::Twox128 => match key_trimmed_data.get(..TWOX128_LEN) {
                Some(hash_part) => {
                    if key_trimmed_data.len() > TWOX128_LEN {
                        return Err(ParserError::KeyPartsUnused);
                    }
                    Ok(KeyData::Single {
                        content: KeyPart::Hash(HashData {
                            hash: Hash::Twox128(hash_part.try_into().expect("stable known length")),
                            type_id: key_ty.id(),
                        }),
                    })
                }
                None => Err(ParserError::DataTooShort),
            },
            StorageHasher::Twox256 => match key_trimmed_data.get(..TWOX256_LEN) {
                Some(hash_part) => {
                    if key_trimmed_data.len() > TWOX256_LEN {
                        return Err(ParserError::KeyPartsUnused);
                    }
                    Ok(KeyData::Single {
                        content: KeyPart::Hash(HashData {
                            hash: Hash::Twox256(hash_part.try_into().expect("stable known length")),
                            type_id: key_ty.id(),
                        }),
                    })
                }
                None => Err(ParserError::DataTooShort),
            },
            StorageHasher::Twox64Concat => match key_trimmed_data.get(..TWOX64_LEN) {
                Some(hash_part) => {
                    if hash_part != twox_64(&key_trimmed_data[TWOX64_LEN..]) {
                        return Err(ParserError::KeyPartHashMesmatch);
                    }
                    *key_trimmed_data = key_trimmed_data[TWOX64_LEN..].to_vec();
                    let parsed_key = decode_with_type(
                        &Ty::Symbol(key_ty),
                        key_trimmed_data,
                        registry,
                        Propagated::new(),
                    )?;
                    if !key_trimmed_data.is_empty() {
                        return Err(ParserError::KeyPartsUnused);
                    }
                    Ok(KeyData::Single {
                        content: KeyPart::Parsed(parsed_key),
                    })
                }
                None => Err(ParserError::DataTooShort),
            },
            StorageHasher::Identity => {
                let parsed_key = decode_with_type(
                    &Ty::Symbol(key_ty),
                    key_trimmed_data,
                    registry,
                    Propagated::new(),
                )?;
                if !key_trimmed_data.is_empty() {
                    return Err(ParserError::KeyPartsUnused);
                }
                Ok(KeyData::Single {
                    content: KeyPart::Parsed(parsed_key),
                })
            }
        }
    } else {
        let key_ty_resolved = resolve_ty(registry, key_ty.id())?;
        let info = Info::from_ty(key_ty_resolved);
        match key_ty_resolved.type_def() {
            TypeDef::Tuple(t) => {
                let tuple_elements = t.fields();
                if tuple_elements.len() != hashers.len() {
                    return Err(ParserError::MultipleHashesNumberMismatch);
                }
                let mut content: Vec<KeyPart> = Vec::new();
                for index in 0..tuple_elements.len() {
                    match hashers[index] {
                        StorageHasher::Blake2_128 => match key_trimmed_data.get(..BLAKE2_128_LEN) {
                            Some(hash_part) => {
                                content.push(KeyPart::Hash(HashData {
                                    hash: Hash::Blake2_128(
                                        hash_part.try_into().expect("stable known length"),
                                    ),
                                    type_id: key_ty.id(),
                                }));
                                *key_trimmed_data = key_trimmed_data[BLAKE2_128_LEN..].to_vec();
                            }
                            None => return Err(ParserError::DataTooShort),
                        },
                        StorageHasher::Blake2_256 => match key_trimmed_data.get(..BLAKE2_256_LEN) {
                            Some(hash_part) => {
                                content.push(KeyPart::Hash(HashData {
                                    hash: Hash::Blake2_256(
                                        hash_part.try_into().expect("stable known length"),
                                    ),
                                    type_id: key_ty.id(),
                                }));
                                *key_trimmed_data = key_trimmed_data[BLAKE2_256_LEN..].to_vec();
                            }
                            None => return Err(ParserError::DataTooShort),
                        },
                        StorageHasher::Blake2_128Concat => {
                            match key_trimmed_data.get(..BLAKE2_128_LEN) {
                                Some(hash_part) => {
                                    let hash_part = hash_part.to_owned();
                                    *key_trimmed_data = key_trimmed_data[BLAKE2_128_LEN..].to_vec();
                                    let mut key_into_parsing = key_trimmed_data.clone();
                                    let parsed_key = decode_with_type(
                                        &Ty::Symbol(&tuple_elements[index]),
                                        &mut key_into_parsing,
                                        registry,
                                        Propagated::new(),
                                    )?;

                                    let into_hash_checker = key_trimmed_data[..]
                                        .strip_suffix(&key_into_parsing[..])
                                        .expect("just cut the part on decoding");
                                    if hash_part != blake2_128(into_hash_checker) {
                                        return Err(ParserError::KeyPartHashMesmatch);
                                    }

                                    *key_trimmed_data = key_into_parsing;

                                    content.push(KeyPart::Parsed(parsed_key))
                                }
                                None => return Err(ParserError::DataTooShort),
                            }
                        }
                        StorageHasher::Twox128 => match key_trimmed_data.get(..TWOX128_LEN) {
                            Some(hash_part) => {
                                content.push(KeyPart::Hash(HashData {
                                    hash: Hash::Twox128(
                                        hash_part.try_into().expect("stable known length"),
                                    ),
                                    type_id: key_ty.id(),
                                }));
                                *key_trimmed_data = key_trimmed_data[TWOX128_LEN..].to_vec();
                            }
                            None => return Err(ParserError::DataTooShort),
                        },
                        StorageHasher::Twox256 => match key_trimmed_data.get(..TWOX256_LEN) {
                            Some(hash_part) => {
                                content.push(KeyPart::Hash(HashData {
                                    hash: Hash::Twox256(
                                        hash_part.try_into().expect("stable known length"),
                                    ),
                                    type_id: key_ty.id(),
                                }));
                                *key_trimmed_data = key_trimmed_data[TWOX256_LEN..].to_vec();
                            }
                            None => return Err(ParserError::DataTooShort),
                        },
                        StorageHasher::Twox64Concat => match key_trimmed_data.get(..TWOX64_LEN) {
                            Some(hash_part) => {
                                let hash_part = hash_part.to_owned();
                                *key_trimmed_data = key_trimmed_data[TWOX64_LEN..].to_vec();
                                let mut key_into_parsing = key_trimmed_data.clone();
                                let parsed_key = decode_with_type(
                                    &Ty::Symbol(&tuple_elements[index]),
                                    &mut key_into_parsing,
                                    registry,
                                    Propagated::new(),
                                )?;

                                let into_hash_checker = key_trimmed_data[..]
                                    .strip_suffix(&key_into_parsing[..])
                                    .expect("just cut the part on decoding");
                                if hash_part != twox_64(into_hash_checker) {
                                    return Err(ParserError::KeyPartHashMesmatch);
                                }

                                *key_trimmed_data = key_into_parsing;

                                content.push(KeyPart::Parsed(parsed_key))
                            }
                            None => return Err(ParserError::DataTooShort),
                        },
                        StorageHasher::Identity => {
                            let parsed_key = decode_with_type(
                                &Ty::Symbol(&tuple_elements[index]),
                                key_trimmed_data,
                                registry,
                                Propagated::new(),
                            )?;
                            content.push(KeyPart::Parsed(parsed_key))
                        }
                    }
                }
                if !key_trimmed_data.is_empty() {
                    return Err(ParserError::KeyPartsUnused);
                }
                Ok(KeyData::Tuple { content, info })
            }
            _ => Err(ParserError::MultipleHashesNotATuple),
        }
    }
}
