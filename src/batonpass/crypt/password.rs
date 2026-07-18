//! `HashedPassword` is an argon2 password hash, held as a PHC string.
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use core::fmt;
use core::str;
use thiserror::Error;

/// The exact length in bytes of the PHC-format string produced by
/// [`HashedPassword::hash`] for the current `Argon2` algorithm/version/params.
/// This is constant because `SaltString::generate` always draws a
/// fixed-length salt and `Argon2::default()` always produces a fixed-length
/// output; only the salt/hash *bytes* vary between calls, never their
/// encoded lengths. Covered by `hash_fixed_length_test`; must be
/// re-verified if the Argon2 params ever change.
pub const PASSWORD_HASH_LEN: usize = 97;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashedPassword(String);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PasswordError {
    #[error("password hash error: {0}")]
    PasswordHash(String),
}

impl HashedPassword {
    /// `hash` produces the argon2 password hash of `s`.
    pub fn hash(s: &str) -> Result<Self, PasswordError> {
        debug_assert!(!s.is_empty());
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(s.as_bytes(), &salt)
            .map_err(|cause| PasswordError::PasswordHash(format!("{cause:?}")))?;
        Ok(Self(hash.to_string()))
    }

    /// `rand` produces the argon2 hash of a randomly generated password.
    pub fn rand() -> Result<Self, PasswordError> {
        Self::hash(&super::rand_hex())
    }

    /// `verify` determines if `s` is the password matching this hash.
    pub fn verify(&self, s: &str) -> Result<bool, PasswordError> {
        match PasswordHash::new(&self.0) {
            Ok(v) => match Argon2::default().verify_password(s.as_bytes(), &v) {
                Ok(()) => Ok(true),
                _ => Ok(false),
            },
            Err(cause) => Err(PasswordError::PasswordHash(format!("{cause:?}"))),
        }
    }
}

impl fmt::Display for HashedPassword {
    /// `fmt` produces the PHC-format string of the `HashedPassword`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl str::FromStr for HashedPassword {
    type Err = PasswordError;

    /// `from_str` builds a `HashedPassword` from a PHC string
    /// assumed to have been built by the `Display` impl.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        PasswordHash::new(raw)
            .map_err(|cause| PasswordError::PasswordHash(format!("{cause:?}")))?;
        Ok(Self(raw.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn hash_and_verify_test() {
        let pw = "my password";
        let hashed = HashedPassword::hash(pw).unwrap();
        let hashed2 = HashedPassword::hash(pw).unwrap();
        assert_ne!(hashed, hashed2); // different salt in hashed, hashed2
        assert!(hashed.verify(pw).unwrap());
        let bad = "not my password";
        assert!(!hashed.verify(bad).unwrap());
    }

    #[test_log::test]
    fn rand_test() {
        let hashed = HashedPassword::rand().unwrap();
        let hashed2 = HashedPassword::rand().unwrap();
        assert_ne!(hashed, hashed2); // different random password + salt
    }

    #[test_log::test]
    fn hash_fixed_length_test() {
        for pw in [
            "a",
            "a much much longer password than the other one",
            "my password",
        ] {
            assert_eq!(
                HashedPassword::hash(pw).unwrap().to_string().len(),
                PASSWORD_HASH_LEN
            );
        }
    }

    #[test_log::test]
    fn round_trip_test() {
        let hashed = HashedPassword::hash("my password").unwrap();
        assert_eq!(
            hashed,
            hashed.to_string().parse::<HashedPassword>().unwrap()
        );
    }
}
