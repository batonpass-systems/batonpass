//! # User
//!
//! `user` is a real human user in batonpass.

use ed25519_dalek::VerifyingKey;
use uuid::Uuid;

use crate::batonpass::crypt::password::HashedPassword;
use crate::batonpass::crypt::sha256digest::Sha256Digest;
use crate::batonpass::model::meta::Meta;

/// `User` has a name, email, password, org and ed25519 public key.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct User {
    pub ed25519_public: VerifyingKey,
    pub ed25519_digest: Sha256Digest,
    pub email: String,
    pub email_digest: Sha256Digest,
    pub name: String,
    pub name_digest: Sha256Digest,
    pub org: Uuid,
    pub password: HashedPassword,
    pub meta: Option<Meta>,
}
