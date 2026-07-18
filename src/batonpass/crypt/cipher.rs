//! `encrypt`/`decrypt` provide AES-GCM encryption using a [`super::key::Key`]
//! and a fresh [`super::nonce::Nonce`] per message.
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use hex;
use thiserror::Error;
use tracing::error;

use super::key::Key;
use super::nonce::Nonce;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AesError {
    #[error("cipher error: {0}")]
    Cipher(String),

    #[error("decode error: {0}")]
    Decode(String),
}

/// `encrypt` produces a hex-encoding of `m` encrypted with
/// `key` and a random nonce.
///
/// The output of this function is the expected encrypted-value input
/// for `decrypt`.
///
/// Example:
/// ```
/// let key = Key::rand().unwrap();
/// let m = "plain";
/// let c = encrypt(&key, m).unwrap();
/// let d = decrypt(&key, &c).unwrap();
/// assert_eq!(&m, &d);
/// ```
pub fn encrypt(key: &Key, m: &str) -> Result<String, AesError> {
    let cipher = Aes256Gcm::new(&key.as_aes_key());
    let nonce = Nonce::rand();
    match cipher.encrypt(nonce.as_aes_nonce(), m.as_bytes()) {
        Ok(v) => Ok(hex::encode([nonce.as_bytes(), v.as_slice()].concat())),
        Err(cause) => Err(AesError::Cipher(format!("{cause:?}"))),
    }
}

/// `decrypt` produces the cleartext of ciphertext `c` using `key`.
pub fn decrypt(key: &Key, c: &str) -> Result<String, AesError> {
    let decoded = match hex::decode(c) {
        Ok(v) => v,
        Err(cause) => return Err(AesError::Decode(format!("decode from hex: {cause:?}"))),
    };
    let cipher = Aes256Gcm::new(&key.as_aes_key());
    let nonce = Nonce::from_slice(&decoded[0..super::nonce::NONCE_LENGTH]);
    match cipher.decrypt(nonce.as_aes_nonce(), &decoded[super::nonce::NONCE_LENGTH..]) {
        Ok(v) => match String::from_utf8(v) {
            Ok(s) => Ok(s),
            Err(cause) => Err(AesError::Decode(format!("decode from utf8: {cause:?}"))),
        },
        Err(cause) => {
            error!("{}", format!("decrypt fail {cause:?}"));
            Err(AesError::Cipher(format!("{cause:?}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn encrypt_decrypt_test() {
        // round trip
        let key = Key::rand();
        let m = "plain text";
        let c = encrypt(&key, m).unwrap();
        assert_ne!(m, &c);
        let d = decrypt(&key, &c).unwrap();
        assert_eq!(m, &d);
        assert_ne!(&d, &c);

        // Encrypt and decrypt with round-tripped key.
        let key_round_trip = key.to_string().parse::<Key>().unwrap();
        let d_round_trip = decrypt(&key_round_trip, &c).unwrap();
        assert_eq!(m, &d_round_trip);

        // Using a different key should not work.
        let other_key = Key::rand();
        assert!(matches!(decrypt(&other_key, &c), Err(AesError::Cipher(_))));
    }
}
