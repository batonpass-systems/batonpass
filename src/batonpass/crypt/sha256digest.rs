//! # `Sha256Digest`
//!
//! `sha256digest` handles storage and encoding of sha256 hashes.
//!
use sha2::{Digest, Sha256};
use std::str;
use thiserror::Error;

pub const SHA256_DIGEST_LENGTH: usize = 32;

/// `Sha256Digest` stores and encodes sha256 hashes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; SHA256_DIGEST_LENGTH]);

#[derive(Debug, Error)]
pub enum Sha256DigestDecodeError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("input must be SHA256_DIGEST_LENGTH")]
    Length,
}

impl Sha256Digest {
    /// `of` creates a `Sha256Digest` for an arbitrary byte array ref.
    pub fn of(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Sha256Digest(result.into()) // GenericArray -> [u8; 32] via Into
    }

    /// `to_hex` produces an owned hexadecimal encoding of the hash.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// `as_bytes` returns a reference to the underlying hash bytes.
    pub fn as_bytes(&self) -> &[u8; SHA256_DIGEST_LENGTH] {
        &self.0
    }
}

impl str::FromStr for Sha256Digest {
    type Err = Sha256DigestDecodeError;

    /// `from_str` builds a `Sha256Digest` from a hex-encoding
    /// as produced by `Display`/`to_hex`.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let bs = hex::decode(raw)?;
        if bs.len() != SHA256_DIGEST_LENGTH {
            return Err(Sha256DigestDecodeError::Length);
        }
        let arr: [u8; SHA256_DIGEST_LENGTH] = bs.try_into().expect("checked length above");
        Ok(Self(arr))
    }
}

impl std::fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
