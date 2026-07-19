//! # Crypt
//!
//! `crypt` provides crypto-related functionality including AES-GCM and password hashing.
#![allow(dead_code, unused_imports)]
use hex;
use rand::RngExt;
use sha2::{Digest, Sha256};

pub mod cipher;
pub mod ed25519;
pub mod key;
pub mod nonce;
pub mod password;
pub mod sha256digest;
pub mod version_key_map;

pub use cipher::{AesError, decrypt, encrypt};
pub use ed25519::{Ed25519PublicDecodeError, decode_ed25519_public};
pub use key::{KEY_LENGTH, Key, KeyDecodeError};
pub use nonce::{NONCE_LENGTH, Nonce};
pub use password::{HashedPassword, PASSWORD_HASH_LEN, PasswordError};
pub use version_key_map::VersionKeyMap;

/// `rand_string` produces a new short random hex `String` (len: 12).
pub fn rand_string() -> String {
    hex::encode(rand::rng().random::<[u8; 6]>().as_slice())
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
}
