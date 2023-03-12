//! [`Compact`] search and processing.
use parity_scale_codec::{Compact, Decode, HasCompact};

use crate::error::ParserError;
use crate::traits::{AddressableBuffer, ExternalMemory};

/// Compact found in data.
pub struct FoundCompact<T: HasCompact> {
    /// Compact found and decoded.
    pub compact: T,

    /// Position of first data element after the compact part.
    pub start_next_unit: usize,
}

/// Maximum possible encoded compact length, `Compact::compact_len(&u128::MAX)`.
///
/// Would not make sense to check slices of higher length for a compact.
pub const MAX_COMPACT_LEN: usize = 17;

/// Search `&[u8]` for compact at given position by brute force.
///
/// Tries to find shortest `[u8]` slice that could be decoded as a compact.
/// Does not modify the input.
pub fn find_compact<T, B, E>(
    data: &B,
    ext_memory: &mut E,
    position: usize,
) -> Result<FoundCompact<T>, ParserError>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    T: HasCompact,
    Compact<T>: Decode,
{
    if data.total_len() < position {
        return Err(ParserError::OutOfRange {
            position,
            total_length: data.total_len(),
        });
    }
    let mut out = None;
    for i in 0..(data.total_len() - position) {
        // checking if length exceeds maximum possible length for a compact
        if i > MAX_COMPACT_LEN {
            break;
        }

        let hippo = data.read_slice(ext_memory, position, i + 1)?;
        let unhippo = <Compact<T>>::decode(&mut hippo.as_ref());
        if let Ok(hurray) = unhippo {
            let start_next_unit = {
                if data.total_len() - position == i {
                    data.total_len()
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
        None => Err(ParserError::NoCompact { position }),
    }
}

/// Find compact and move current parser position accordingly.
pub(crate) fn get_compact<T, B, E>(
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
) -> Result<T, ParserError>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    T: HasCompact,
    Compact<T>: Decode,
{
    let found_compact = find_compact::<T, B, E>(data, ext_memory, *position)?;
    *position = found_compact.start_next_unit;
    Ok(found_compact.compact)
}
