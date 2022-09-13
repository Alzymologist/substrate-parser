//! [`Compact`] search and processing.
use parity_scale_codec::{Compact, Decode, HasCompact};

use crate::error::ParserError;

/// Compact found in data.
pub struct FoundCompact<T: HasCompact> {
    /// Compact found and decoded.
    pub compact: T,

    /// Position of first data element after the compact part, if any.
    pub start_next_unit: Option<usize>,
}

/// Search `&[u8]` for compact by brute force.
///
/// Tries to find shortest `[u8]` slice that could be decoded as a compact.
/// Does not modify the input.
pub fn find_compact<T>(data: &[u8]) -> Result<FoundCompact<T>, ParserError>
where
    T: HasCompact,
    Compact<T>: Decode,
{
    if data.is_empty() {
        return Err(ParserError::DataTooShort);
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
            out = Some(FoundCompact {
                compact: hurray.0,
                start_next_unit,
            });
            break;
        }
    }
    match out {
        Some(c) => Ok(c),
        None => Err(ParserError::NoCompact),
    }
}

/// Find compact and cut it from the input data.
pub(crate) fn get_compact<T>(data: &mut Vec<u8>) -> Result<T, ParserError>
where
    T: HasCompact,
    Compact<T>: Decode,
{
    let found_compact = find_compact::<T>(data)?;
    *data = match found_compact.start_next_unit {
        Some(start) => data[start..].to_vec(),
        None => Vec::new(),
    };
    Ok(found_compact.compact)
}
