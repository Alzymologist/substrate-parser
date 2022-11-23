//! Types and functions for `no_std` only.
//!
//! Exactly follow current substrate code from `no_std` incompatible crates. Last confirmed on v7.0.0
#[cfg(feature = "embed-display")]
use base58::ToBase58;
use parity_scale_codec::{Decode, Error, Input};

pub use crate::special_types::{SIGNATURE_LEN_ECDSA, SIGNATURE_LEN_ED25519, SIGNATURE_LEN_SR25519};

#[cfg(feature = "embed-display")]
use crate::std::{string::String, vec::Vec};

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

/// Definitions for some special arrays from `sp_core`.
macro_rules! define_array {
    ($(#[$attr:meta] $name: ident ($len: expr)), *) => {
        $(
            #[$attr]
            ///
            /// Intended for `no_std`, for decoding and display of decoded data only.
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct $name(pub [u8; $len]);
            impl $name {
                pub const fn len_bytes() -> usize {
		    $len
		}
            }
        )*
    }
}

/// Known size for `sp_core::crypto::AccountId32`.
pub const ACCOUNT_ID_32_LEN: usize = 32;

/// Known size for `sp_core::ed25519::Public`.
pub const PUBLIC_LEN_ED25519: usize = 32;

/// Known size for `sp_core::sr25519::Public`.
pub const PUBLIC_LEN_SR25519: usize = 32;

/// Known size for `sp_core::ecdsa::Public`.
pub const PUBLIC_LEN_ECDSA: usize = 33;

define_array! {
    /// Placeholder for `sp_core::crypto::AccountId32`.
    AccountId32(ACCOUNT_ID_32_LEN)
}
define_array! {
    /// Placeholder for `sp_core::ed25519::Public`.
    PublicEd25519(PUBLIC_LEN_ED25519)
}
define_array! {
    /// Placeholder for `sp_core::sr25519::Public`.
    PublicSr25519(PUBLIC_LEN_SR25519)
}
define_array! {
    /// Placeholder for `sp_core::ecdsa::Public`.
    PublicEcdsa(PUBLIC_LEN_ECDSA)
}
define_array! {
    /// Placeholder for `sp_core::ed25519::Signature`.
    SignatureEd25519(SIGNATURE_LEN_ED25519)
}
define_array! {
    /// Placeholder for `sp_core::sr25519::Signature`.
    SignatureSr25519(SIGNATURE_LEN_SR25519)
}
define_array! {
    /// Placeholder for `sp_core::ecdsa::Signature`.
    SignatureEcdsa(SIGNATURE_LEN_ECDSA)
}

/// Prefix used in base58 conversion. From `sp_core`.
#[cfg(feature = "embed-display")]
const PREFIX: &[u8] = b"SS58PRE";

/// Hash calculation used in base58 conversion. From `sp_core`.
#[cfg(feature = "embed-display")]
fn ss58hash(data: &[u8]) -> Vec<u8> {
    use blake2::{Blake2b512, Digest};

    let mut ctx = Blake2b512::new();
    ctx.update(PREFIX);
    ctx.update(data);
    ctx.finalize().to_vec()
}

/// Same as `to_ss58check_with_version()` method for `Ss58Codec`.
///
/// Comments also from `sp_core`.
#[cfg(feature = "embed-display")]
fn as_base58_with_known_prefix(input: &[u8], base58prefix: u16) -> String {
    // We mask out the upper two bits of the ident - SS58 Prefix currently only supports 14-bits
    let ident: u16 = base58prefix & 0b0011_1111_1111_1111;
    let mut v = match ident {
        0..=63 => vec![ident as u8],
        64..=16_383 => {
            // upper six bits of the lower byte(!)
            let first = ((ident & 0b0000_0000_1111_1100) as u8) >> 2;
            // lower two bits of the lower byte in the high pos,
            // lower bits of the upper byte in the low pos
            let second = ((ident >> 8) as u8) | ((ident & 0b0000_0000_0000_0011) as u8) << 6;
            vec![first | 0b01000000, second]
        }
        _ => unreachable!("masked out the upper two bits; qed"),
    };
    v.extend(input);
    let r = ss58hash(&v);
    v.extend(&r[0..2]);
    v.to_base58()
}

/// Base58 representation for some special arrays from `sp_core`.
#[cfg(feature = "embed-display")]
macro_rules! add_base {
    ($($name: ident), *) => {
        $(
            impl $name {
		pub fn as_base58(&self, base58prefix: u16) -> String {
		    as_base58_with_known_prefix(&self.0, base58prefix)
		}
            }
        )*
    }
}

#[cfg(feature = "embed-display")]
add_base!(AccountId32, PublicEd25519, PublicSr25519, PublicEcdsa);

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
