//! # `Signature`
//!
//! `signature` handles storage and decoding of database row signatures.
use std::str;
use thiserror::Error;

pub const SIGNATURE_LENGTH: usize = 16;

/// `Signature` is a unique stamp from the database, used
/// to identify a unique row version. It is the raw bytes of
/// an md5 hex-encoding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

#[derive(Debug, Error)]
pub enum SignatureDecodeError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("input must be SIGNATURE_LENGTH")]
    Length,
}

impl str::FromStr for Signature {
    type Err = SignatureDecodeError;

    /// `from_str` builds a `Signature` from an md5 hex-encoding
    /// as read from the database.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let bs = hex::decode(raw)?;
        if bs.len() != SIGNATURE_LENGTH {
            return Err(SignatureDecodeError::Length);
        }
        let arr: [u8; SIGNATURE_LENGTH] = bs.try_into().expect("checked length above");
        Ok(Self(arr))
    }
}
