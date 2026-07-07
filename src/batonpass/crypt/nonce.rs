//! `Nonce` is the per-message value used by [`super::cipher`] to keep
//! AES-GCM ciphertexts produced with the same [`super::key::Key`] distinct.
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadCore, array::Array},
};
use rand::RngExt;

pub const NONCE_LENGTH: usize = 12;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Nonce([u8; NONCE_LENGTH]);

impl Nonce {
    pub fn rand() -> Self {
        Self(rand::rng().random::<[u8; NONCE_LENGTH]>())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(super) fn from_slice(bytes: &[u8]) -> Self {
        let arr: [u8; NONCE_LENGTH] = bytes.try_into().expect("nonce length");
        Self(arr)
    }

    pub(super) fn as_aes_nonce(&self) -> &Array<u8, <Aes256Gcm as AeadCore>::NonceSize> {
        self.0.as_slice().try_into().expect("nonce length")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn nonce_rand_length_test() {
        assert_eq!(Nonce::rand().as_bytes().len(), NONCE_LENGTH);
    }

    #[test_log::test]
    fn nonce_from_slice_round_trip_test() {
        let n = Nonce::rand();
        let n2 = Nonce::from_slice(n.as_bytes());
        assert_eq!(n, n2);
    }
}
