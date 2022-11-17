//! Types and functions for `no_std` only.
//!
//! Exactly follow current substrate code from `no_std` incompatible crates.
use parity_scale_codec::{Decode, Error, Input};

/// Era period, same as in `sp_runtime::generic`.
pub type Period = u64;

/// Era phase, same as in `sp_runtime::generic`.
pub type Phase = u64;

/// Era, same as in `sp_runtime::generic::Era`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Era {
    Immortal,
    Mortal(Period, Phase),
}

/// [`Decode`] implementation, same as in `sp_runtime::generic::Era`.
impl Decode for Era {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let first = input.read_byte()?;
        if first == 0 {
            Ok(Self::Immortal)
        } else {
            let encoded = first as u64 + ((input.read_byte()? as u64) << 8);
            let period = 2 << (encoded % (1 << 4));
            let quantize_factor = (period >> 12).max(1);
            let phase = (encoded >> 4) * quantize_factor;
            if period >= 4 && phase < period {
                Ok(Self::Mortal(period, phase))
            } else {
                Err("Invalid period and phase".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn era01() {
        let data = [0];
        let era = Era::decode(&mut &data[..]).unwrap();
        assert_eq!(era, Era::Immortal);
    }

    #[test]
    fn era02() {
        let data = hex::decode("b501").unwrap();
        let era = Era::decode(&mut &data[..]).unwrap();
        assert_eq!(era, Era::Mortal(64, 27));
    }

    #[test]
    fn era03() {
        let data = hex::decode("1111").unwrap();
        assert!(Era::decode(&mut &data[..]).is_err());
    }
}
