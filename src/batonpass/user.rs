//! # User
//!
//! `user` is a real human user in batonpass.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use uuid::Uuid;

use crate::batonpass::crypt::password::HashedPassword;
use crate::batonpass::crypt::rand_string;
use crate::batonpass::crypt::sha256digest::Sha256Digest;
use crate::batonpass::model::meta::Meta;

/// `User` has a name, email, password, org and ed25519 public key.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct User {
    pub ed25519_public: VerifyingKey,
    pub ed25519_public_digest: Sha256Digest,
    pub email: String,
    pub email_digest: Sha256Digest,
    pub name: String,
    pub name_digest: Sha256Digest,
    pub org: Uuid,
    pub password: HashedPassword,
    pub meta: Option<Meta>,
}

impl User {
    #[allow(dead_code)]
    pub fn new(
        ed25519_public: VerifyingKey,
        email: String,
        name: String,
        org: Uuid,
        password: HashedPassword,
        meta: Option<Meta>,
    ) -> Self {
        let email_digest = Sha256Digest::of(email.as_bytes());
        let name_digest = Sha256Digest::of(name.as_bytes());
        Self {
            ed25519_public,
            ed25519_public_digest: Sha256Digest::of(ed25519_public.as_bytes()),
            email,
            email_digest,
            name,
            name_digest,
            org,
            password,
            meta,
        }
    }

    #[allow(dead_code)]
    pub fn test() -> (Self, SigningKey) {
        let mut csprng = UnwrapErr(SysRng);
        let signing_key = SigningKey::generate(&mut csprng); // private key
        let verifying_key = signing_key.verifying_key(); // public key
        (
            Self::new(
                verifying_key,
                rand_string(),
                rand_string(),
                Uuid::now_v7(),
                HashedPassword::rand().expect("rand password"),
                None,
            ),
            signing_key,
        )
    }
}
