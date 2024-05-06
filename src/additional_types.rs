//! Types and functions from [`sp_core`](https://docs.rs/sp-core/latest/sp_core/)
//! and [`sp_runtime`](https://docs.rs/sp-runtime/latest/sp_runtime/).
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

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

/// [`Encode`] implementation, same as in `sp_runtime::generic::Era`.
impl Encode for Era {
    fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
        match self {
            Self::Immortal => output.push_byte(0),
            Self::Mortal(period, phase) => {
                let quantize_factor = (*period >> 12).max(1);
                let encoded = (period.trailing_zeros() - 1).clamp(1, 15) as u16
                    | ((phase / quantize_factor) << 4) as u16;
                encoded.encode_to(output);
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
