//! # `ed25519`
//!
//! `ed25519` handles decoding of ed25519 public keys as stored in the database.
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SignatureError, VerifyingKey};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum Ed25519PublicDecodeError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("input must be PUBLIC_KEY_LENGTH")]
    Length,

    #[error(transparent)]
    Signature(#[from] SignatureError),
}

/// `decode_ed25519_public` builds a `VerifyingKey` from a hex-encoding
/// as read from the database.
#[allow(dead_code)]
pub fn decode_ed25519_public(raw: &str) -> Result<VerifyingKey, Ed25519PublicDecodeError> {
    let bs = hex::decode(raw)?;
    if bs.len() != PUBLIC_KEY_LENGTH {
        return Err(Ed25519PublicDecodeError::Length);
    }
    let arr: [u8; PUBLIC_KEY_LENGTH] = bs.try_into().expect("checked length above");
    Ok(VerifyingKey::from_bytes(&arr)?)
}
