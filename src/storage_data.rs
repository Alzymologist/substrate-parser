//! Interpret storage data.
//!
//! Chain storage could be queried by rpc `state_getStorage`.
//!
//! Query key has prefix built from `prefix` of
//! [`PalletStorageMetadata`](frame_metadata::v14::PalletStorageMetadata) and
//! `name` of
//! [`StorageEntryMetadata`](frame_metadata::v14::StorageEntryMetadata), both
//! processed as bytes in [`twox_128`](sp_core::twox_128) and concatenated
//! together. Remaining path of the query key and the associated value are
//! described in corresponding [`StorageEntryType`] and are processed here.
use frame_metadata::v14::{StorageEntryMetadata, StorageEntryType, StorageHasher};
use scale_info::{form::PortableForm, interner::UntrackedSymbol, PortableRegistry, TypeDef};
use sp_core::{blake2_128, twox_64};

use crate::cards::{Documented, ExtendedData, Info};
use crate::decode_blob_as_type;
use crate::decoding_sci::{decode_with_type, resolve_ty, Ty};
use crate::error::{ParserError, StorageError};
use crate::propagated::Propagated;

/// Parsed storage entry data: key, value, general docs.
#[derive(Debug, Eq, PartialEq)]
pub struct Storage {
    /// Storage key data.
    pub key: KeyData,

    /// Storage value decoded.
    pub value: ExtendedData,

    /// documentation common for all storage entries with the same prefix.
    pub docs: String,
}

/// Processed key.
#[derive(Debug, Eq, PartialEq)]
pub enum KeyData {
    /// Plain storage. Key contains only prefix, no additional data.
    Plain,

    /// Map storage with a single [`StorageHasher`].
    ///
    /// Key contains prefix and a single hash. No restrictions on key type.
    SingleHash {
        /// Processed key data.
        content: KeyPart,
    },

    /// Map storage with a set of [`StorageHasher`]s.
    ///
    /// Key contains prefix and a set of hashes. Associated key is expected to
    /// be a tuple type.
    TupleHash {
        /// Set of processed key elements. Has the same number of elements as
        /// the set of [`StorageHasher`]s.
        content: Vec<KeyPart>,

        /// [`Info`] associated with key type as a whole.
        info: Info,
    },
}

/// Processed key part.
#[derive(Debug, Eq, PartialEq)]
pub enum KeyPart {
    /// Hash has no concatenated raw part, no data decoded.
    Hash(HashData),

    /// Hash decoded.
    Parsed(ExtendedData),
}

/// Data for hash that was not decoded.
#[derive(Debug, Eq, PartialEq)]
pub struct HashData {
    /// Hash itself.
    pub hash: Hash,

    /// Associated type id in `PortableRegistry`.
    pub type_id: u32,
}

/// Raw hashes.
#[derive(Debug, Eq, PartialEq)]
pub enum Hash {
    Blake2_128([u8; BLAKE2_128_LEN]),
    Blake2_256([u8; BLAKE2_256_LEN]),
    Twox128([u8; TWOX128_LEN]),
    Twox256([u8; TWOX256_LEN]),
}

/// Lenght in bytes for Blake2_128 hash.
pub const BLAKE2_128_LEN: usize = 16;

/// Lenght in bytes for Blake2_256 hash.
pub const BLAKE2_256_LEN: usize = 32;

/// Lenght in bytes for Twox_128 hash.
pub const TWOX128_LEN: usize = 16;

/// Lenght in bytes for Twox_256 hash.
pub const TWOX256_LEN: usize = 32;

/// Lenght in bytes for Twox_64 hash.
pub const TWOX64_LEN: usize = 8;

/// Parse a storage entry (both the key and the corresponding value).
///
/// Both the key and the value are expected to get processed completely, i.e.
/// with no data remaining.
pub fn decode_as_storage_entry(
    key_trimmed_data: &[u8],
    value_data: &[u8],
    entry_metadata: &StorageEntryMetadata<PortableForm>,
    registry: &PortableRegistry,
) -> Result<Storage, StorageError> {
    let docs = entry_metadata.collect_docs();
    let (key, value) = match &entry_metadata.ty {
        StorageEntryType::Plain(value_ty) => {
            if !key_trimmed_data.is_empty() {
                return Err(StorageError::PlainKeyExceedsPrefix);
            }
            let key = KeyData::Plain;
            let value = decode_blob_as_type(value_ty, value_data, registry)
                .map_err(StorageError::Parsing)?;
            (key, value)
        }
        StorageEntryType::Map {
            hashers,
            key: key_ty,
            value: value_ty,
        } => {
            let key = process_key(hashers, key_ty, key_trimmed_data, registry)?;
            let value = decode_blob_as_type(value_ty, value_data, registry)
                .map_err(StorageError::Parsing)?;
            (key, value)
        }
    };
    Ok(Storage { key, value, docs })
}

macro_rules! cut_hash {
    ($func:ident, $hash_len:ident, $enum_variant:ident) => {
        fn $func(
            key_ty: &UntrackedSymbol<std::any::TypeId>,
            key_trimmed_data: &[u8],
            position: &mut usize,
        ) -> Result<KeyPart, StorageError> {
            match key_trimmed_data.get(*position..*position + $hash_len) {
                Some(slice) => {
                    let hash_part: [u8; $hash_len] =
                        slice.try_into().expect("constant length, always fits");
                    *position += $hash_len;
                    Ok(KeyPart::Hash(HashData {
                        hash: Hash::$enum_variant(hash_part),
                        type_id: key_ty.id(),
                    }))
                }
                None => Err(StorageError::Parsing(ParserError::DataTooShort)),
            }
        }
    };
}

cut_hash!(cut_blake2_128, BLAKE2_128_LEN, Blake2_128);
cut_hash!(cut_blake2_256, BLAKE2_256_LEN, Blake2_256);
cut_hash!(cut_twox_128, TWOX128_LEN, Twox128);
cut_hash!(cut_twox_256, TWOX256_LEN, Twox256);

macro_rules! check_hash {
    ($func:ident, $hash_len:ident, $fn_into:ident) => {
        fn $func(
            ty: &UntrackedSymbol<std::any::TypeId>,
            key_trimmed_data: &[u8],
            position: &mut usize,
            registry: &PortableRegistry,
        ) -> Result<KeyPart, StorageError> {
            match key_trimmed_data.get(*position..*position + $hash_len) {
                Some(slice) => {
                    let hash_part: [u8; $hash_len] =
                        slice.try_into().expect("constant length, always fits");
                    *position += $hash_len;
                    let position_decoder_starts = *position;
                    let parsed_key = decode_with_type(
                        &Ty::Symbol(&ty),
                        key_trimmed_data,
                        position,
                        registry,
                        Propagated::new(),
                    )
                    .map_err(StorageError::Parsing)?;
                    if hash_part != $fn_into(&key_trimmed_data[position_decoder_starts..*position])
                    {
                        return Err(StorageError::KeyPartHashMismatch);
                    }
                    Ok(KeyPart::Parsed(parsed_key))
                }
                None => Err(StorageError::Parsing(ParserError::DataTooShort)),
            }
        }
    };
}

check_hash!(check_blake2_128, BLAKE2_128_LEN, blake2_128);
check_hash!(check_twox_64, TWOX64_LEN, twox_64);

/// Process the key.
///
/// The key here is trimmed, i.e. the prefix is already removed.
///
/// Key is expected to get processed completely, i.e. with no data remaining.
pub fn process_key(
    hashers: &[StorageHasher],
    key_ty: &UntrackedSymbol<std::any::TypeId>,
    key_trimmed_data: &[u8],
    registry: &PortableRegistry,
) -> Result<KeyData, StorageError> {
    let mut position: usize = 0;
    let key_data = {
        if hashers.len() == 1 {
            match hashers[0] {
                StorageHasher::Blake2_128 => KeyData::SingleHash {
                    content: cut_blake2_128(key_ty, key_trimmed_data, &mut position)?,
                },
                StorageHasher::Blake2_256 => KeyData::SingleHash {
                    content: cut_blake2_256(key_ty, key_trimmed_data, &mut position)?,
                },
                StorageHasher::Blake2_128Concat => KeyData::SingleHash {
                    content: check_blake2_128(key_ty, key_trimmed_data, &mut position, registry)?,
                },
                StorageHasher::Twox128 => KeyData::SingleHash {
                    content: cut_twox_128(key_ty, key_trimmed_data, &mut position)?,
                },
                StorageHasher::Twox256 => KeyData::SingleHash {
                    content: cut_twox_256(key_ty, key_trimmed_data, &mut position)?,
                },
                StorageHasher::Twox64Concat => KeyData::SingleHash {
                    content: check_twox_64(key_ty, key_trimmed_data, &mut position, registry)?,
                },
                StorageHasher::Identity => {
                    let parsed_key = decode_with_type(
                        &Ty::Symbol(key_ty),
                        key_trimmed_data,
                        &mut position,
                        registry,
                        Propagated::new(),
                    )
                    .map_err(StorageError::Parsing)?;
                    KeyData::SingleHash {
                        content: KeyPart::Parsed(parsed_key),
                    }
                }
            }
        } else {
            let key_ty_resolved =
                resolve_ty(registry, key_ty.id()).map_err(StorageError::Parsing)?;
            let info = Info::from_ty(key_ty_resolved);
            match key_ty_resolved.type_def() {
                TypeDef::Tuple(t) => {
                    let tuple_elements = t.fields();
                    if tuple_elements.len() != hashers.len() {
                        return Err(StorageError::MultipleHashesNumberMismatch);
                    }
                    let mut content: Vec<KeyPart> = Vec::new();
                    for index in 0..tuple_elements.len() {
                        match hashers[index] {
                            StorageHasher::Blake2_128 => content.push(cut_blake2_128(
                                &tuple_elements[index],
                                key_trimmed_data,
                                &mut position,
                            )?),
                            StorageHasher::Blake2_256 => content.push(cut_blake2_256(
                                &tuple_elements[index],
                                key_trimmed_data,
                                &mut position,
                            )?),
                            StorageHasher::Blake2_128Concat => content.push(check_blake2_128(
                                &tuple_elements[index],
                                key_trimmed_data,
                                &mut position,
                                registry,
                            )?),
                            StorageHasher::Twox128 => content.push(cut_twox_128(
                                &tuple_elements[index],
                                key_trimmed_data,
                                &mut position,
                            )?),
                            StorageHasher::Twox256 => content.push(cut_twox_256(
                                &tuple_elements[index],
                                key_trimmed_data,
                                &mut position,
                            )?),
                            StorageHasher::Twox64Concat => content.push(check_twox_64(
                                &tuple_elements[index],
                                key_trimmed_data,
                                &mut position,
                                registry,
                            )?),
                            StorageHasher::Identity => {
                                let parsed_key = decode_with_type(
                                    &Ty::Symbol(&tuple_elements[index]),
                                    key_trimmed_data,
                                    &mut position,
                                    registry,
                                    Propagated::new(),
                                )
                                .map_err(StorageError::Parsing)?;
                                content.push(KeyPart::Parsed(parsed_key))
                            }
                        }
                    }
                    KeyData::TupleHash { content, info }
                }
                _ => return Err(StorageError::MultipleHashesNotATuple),
            }
        }
    };
    if position == key_trimmed_data.len() {
        Ok(key_data)
    } else {
        Err(StorageError::KeyPartsUnused)
    }
}
