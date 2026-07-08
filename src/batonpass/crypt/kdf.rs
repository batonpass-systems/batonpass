//! `kdf`/`kdf_verify` provide argon2-based password hashing and verification.
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use thiserror::Error;

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

/// `random_password` produces the argon2 hash of a randomly generated password.
#[tracing::instrument]
pub fn random_password() -> Result<String, KdfError> {
    kdf(&super::rand_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn random_password_test() {
        let hashed = random_password().unwrap();
        let hashed2 = random_password().unwrap();
        assert_ne!(hashed, hashed2); // different random password + salt
    }
}
