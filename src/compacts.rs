//! Decoder elements common for all metadata versions
//!
use parity_scale_codec::{Compact, Decode, HasCompact};

use crate::error::{ParserDecodingError, ParserError};

/// Struct to store results of searching Vec<u8> for encoded compact:
/// consists of actual number decoded, and, if it exists, the beginning position for data after the compact
pub struct CutCompact<T: HasCompact> {
    pub compact_found: T,
    pub start_next_unit: Option<usize>,
}

pub fn cut_compact<T>(data: &[u8]) -> Result<CutCompact<T>, ParserError>
where
    T: HasCompact,
    Compact<T>: Decode,
{
    if data.is_empty() {
        return Err(ParserError::Decoding(ParserDecodingError::DataTooShort));
    }
    let mut out = None;
    for i in 0..data.len() {
        let mut hippo = &data[..=i];
        let unhippo = <Compact<T>>::decode(&mut hippo);
        if let Ok(hurray) = unhippo {
            let start_next_unit = {
                if data.len() == i {
                    None
                } else {
                    Some(i + 1)
                }
            };
            out = Some(CutCompact {
                compact_found: hurray.0,
                start_next_unit,
            });
            break;
        }
    }
    match out {
        Some(c) => Ok(c),
        None => Err(ParserError::Decoding(ParserDecodingError::NoCompact)),
    }
}

/// Function to search &[u8] for shortest compact <T> by brute force.
/// Outputs CutCompact value in case of success.
pub fn get_compact<T>(data: &mut Vec<u8>) -> Result<T, ParserError>
where
    T: HasCompact,
    Compact<T>: Decode,
{
    let cut_compact = cut_compact::<T>(data)?;
    *data = match cut_compact.start_next_unit {
        Some(start) => data[start..].to_vec(),
        None => Vec::new(),
    };
    Ok(cut_compact.compact_found)
}
