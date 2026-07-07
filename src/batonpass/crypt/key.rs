//! `Key` is the symmetric encryption key used by [`super::cipher`].
use aes_gcm::Aes256Gcm;
use hex;
use rand::RngExt;
use std::fmt;
use std::str;
use thiserror::Error;

pub const KEY_LENGTH: usize = 32;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Key([u8; KEY_LENGTH]);

impl Key {
    pub fn rand() -> Self {
        Self(rand::rng().random::<[u8; KEY_LENGTH]>())
    }

    pub(super) fn as_aes_key(&self) -> aes_gcm::Key<Aes256Gcm> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn round_trip_key_test() {
        let key = Key::rand();
        assert_eq!(&key, &key.to_string().parse::<Key>().unwrap());
    }
}
