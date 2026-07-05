//! # Crypt
//!
//! `crypt` provides crypto-related functionality including AES-GCM and kdf.
#![allow(dead_code)]
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, array::Array},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use hex;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::str;
use thiserror::Error;
use tracing::error;
use uuid::Uuid;

use crate::batonpass::env;

pub const KEY_LENGTH: usize = 32;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Key([u8; KEY_LENGTH]);

impl Key {
    pub fn rand() -> Self {
        Self(rand::rng().random::<[u8; KEY_LENGTH]>())
    }

    fn as_aes_key(&self) -> aes_gcm::Key<Aes256Gcm> {
        self.0.into()
    }
}

impl fmt::Display for Key {
    /// `fmt` produces a hex-encoding of the `Key`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Error)]
pub enum KeyDecodeError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("input must be KEY_LENGTH")]
    Length,

    #[error("convert byte slice to array: {0}")]
    TryInto(String),
}

impl str::FromStr for Key {
    type Err = KeyDecodeError;

    /// `from_str` builds a `Key` from a (hex) string
    /// assumed to have been built by the `Display` impl.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let bs = hex::decode(raw)?;
        if bs.len() != KEY_LENGTH {
            return Err(KeyDecodeError::Length);
        }
        let _: [u8; KEY_LENGTH] = match bs.try_into() {
            Ok(v) => return Ok(Self(v)),
            Err(cause) => return Err(KeyDecodeError::TryInto(format!("{cause:?}"))),
        };
    }
}

#[derive(Clone, Debug)]
pub struct VersionKeyMap {
    pub keymap: HashMap<Uuid, Key>,
    pub current_version: Uuid,
}

impl VersionKeyMap {
    pub fn new(level: env::Level) -> Self {
        match level {
            env::Level::Test => Self::test(),
            // for when we add other environment levels...
            // _ => panic!("no VersionKeyMap constructor"),
        }
    }

    /// `test` returns a `VersionKeyMap` instance for unit tests.
    pub fn test() -> Self {
        let mut m: HashMap<Uuid, Key> = HashMap::new();
        // Insert a random key, which is not going to be set as current.
        _ = m.insert(Uuid::now_v7(), Key::rand());
        // Insert a random key, which is the current key.
        let current_version = Uuid::now_v7();
        _ = m.insert(current_version, Key::rand());
        Self {
            keymap: m,
            current_version,
        }
    }

    /// `get` performs a `get` on the interior `HashMap`.
    pub fn get(&self, version: Uuid) -> Option<&Key> {
        self.keymap.get(&version)
    }
}

pub const NONCE_LENGTH: usize = 12;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AesError {
    #[error("cipher error: {0}")]
    Cipher(String),

    #[error("decode error: {0}")]
    Decode(String),
}

/// `encrypt` produces a hex-encoding of `m` encrypted with
/// `key` and `nonce`.
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
#[tracing::instrument]
pub fn encrypt(key: &Key, m: &str) -> Result<String, AesError> {
    let cipher = Aes256Gcm::new(&key.as_aes_key());
    let nonce = rand::rng().random::<[u8; NONCE_LENGTH]>();
    let nonce_arr: &Array<u8, _> = nonce.as_slice().try_into().expect("nonce length");
    match cipher.encrypt(nonce_arr, m.as_bytes()) {
        Ok(v) => Ok(hex::encode([nonce.as_slice(), v.as_slice()].concat())),
        Err(cause) => Err(AesError::Cipher(format!("{cause:?}"))),
    }
}

/// `decrypt` produces the cleartext of ciphertext `c` using `key`.
#[tracing::instrument]
pub fn decrypt(key: &Key, c: &str) -> Result<String, AesError> {
    let decoded = match hex::decode(c) {
        Ok(v) => v,
        Err(cause) => return Err(AesError::Decode(format!("decode from hex: {cause:?}"))),
    };
    let cipher = Aes256Gcm::new(&key.as_aes_key());
    let nonce_arr: &Array<u8, _> = decoded[0..NONCE_LENGTH].try_into().expect("nonce length");
    match cipher.decrypt(nonce_arr, &decoded[NONCE_LENGTH..]) {
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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum KdfError {
    #[error("password hash error: {0}")]
    PasswordHash(String),
}

/// `kdf` produces the argon2 password hash of `s`.
#[tracing::instrument]
pub fn kdf(s: &str) -> Result<String, KdfError> {
    debug_assert!(!s.is_empty());
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(s.as_bytes(), &salt) {
        Ok(v) => Ok(v.to_string()),
        Err(cause) => Err(KdfError::PasswordHash(format!("{cause:?}"))),
    }
}

/// `kdf_verify` determines if `s` is the password matching
/// `hashed` (produced by `kdf`).
#[tracing::instrument]
pub fn kdf_verify(s: &str, hashed: &str) -> Result<bool, KdfError> {
    match PasswordHash::new(hashed) {
        Ok(v) => match Argon2::default().verify_password(s.as_bytes(), &v) {
            Ok(()) => Ok(true),
            _ => Ok(false),
        },
        Err(cause) => Err(KdfError::PasswordHash(format!("{cause:?}"))),
    }
}

/// `rand_hex` produces a new random hex `String` (len: 64).
pub fn rand_hex() -> String {
    hex::encode(rand::rng().random::<[u8; KEY_LENGTH]>().as_slice())
}

/// `sha256_hex` produces a hex-encoding of the sha256 of `s`.
pub fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    hex::encode(result.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn round_trip_key_test() {
        let key = Key::rand();
        assert_eq!(&key, &key.to_string().parse::<Key>().unwrap());
    }

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

    #[test_log::test]
    fn kdf_test() {
        let pw = "my password";
        let hashed = kdf(pw).unwrap();
        let hashed2 = kdf(pw).unwrap();
        assert_ne!(hashed, hashed2); // different salt in hashed, hashed2
        assert!(kdf_verify(pw, &hashed).unwrap());
        let bad = "not my password";
        assert!(!kdf_verify(bad, &hashed).unwrap());
    }

    #[test_log::test]
    fn rand_hex_test() {
        assert_eq!(rand_hex().len(), 64);
    }

    #[test_log::test]
    fn sha256_hex_test() {
        assert_eq!(
            sha256_hex("hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test_log::test]
    fn versionkeymap_test() {
        let vk = VersionKeyMap::new(env::Level::Test);
        assert!(vk.get(vk.current_version).is_some());
    }
}
