//! [`Compact`] search and processing.
use parity_scale_codec::{Compact, Decode, HasCompact};

use crate::error::ParserError;

/// Compact found in data.
pub struct FoundCompact<T: HasCompact> {
    /// Compact found and decoded.
    pub compact: T,

    /// Position of first data element after the compact part.
    pub start_next_unit: usize,
}

/// Search `&[u8]` for compact at given position by brute force.
///
/// Tries to find shortest `[u8]` slice that could be decoded as a compact.
/// Does not modify the input.
pub fn find_compact<T>(data: &[u8], position: usize) -> Result<FoundCompact<T>, ParserError>
where
    T: HasCompact,
    Compact<T>: Decode,
{
    if data.len() < position {
        return Err(ParserError::DataTooShort);
    }
    let mut out = None;
    for i in 0..(data.len() - position) {
        let mut hippo = &data[position..=position + i];
        let unhippo = <Compact<T>>::decode(&mut hippo);
        if let Ok(hurray) = unhippo {
            let start_next_unit = {
                if data.len() - position == i {
                    data.len()
                } else {
                    position + i + 1
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
pub(crate) fn get_compact<T>(data: &[u8], position: &mut usize) -> Result<T, ParserError>
where
    T: HasCompact,
    Compact<T>: Decode,
{
    let found_compact = find_compact::<T>(data, *position)?;
    *position = found_compact.start_next_unit;
    Ok(found_compact.compact)
}
