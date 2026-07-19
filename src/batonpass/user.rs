//! # User
//!
//! `user` is a real human user in batonpass.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use std::convert::TryFrom;
use thiserror::Error;
use uuid::Uuid;

use crate::batonpass::crypt::ed25519::{Ed25519PublicDecodeError, decode_ed25519_public};
use crate::batonpass::crypt::password::{HashedPassword, PasswordError};
use crate::batonpass::crypt::rand_string;
use crate::batonpass::crypt::sha256digest::{Sha256Digest, Sha256DigestDecodeError};
use crate::batonpass::crypt::signature::SignatureDecodeError;
use crate::batonpass::model::meta::{HasMeta, Meta};
use crate::batonpass::model::role::{Role, RoleError};
use crate::batonpass::model::status::{Status, StatusError};

/// `NewUser` has a name, email, password, org and ed25519 public key.
/// This is a user that has not yet been inserted.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct NewUser {
    pub ed25519_public: VerifyingKey,
    pub ed25519_public_digest: Sha256Digest,
    pub email: String,
    pub email_digest: Sha256Digest,
    pub name: String,
    pub name_digest: Sha256Digest,
    pub org: Uuid,
    pub password: HashedPassword,
}

impl NewUser {
    /// `new` constructs a `NewUser` given a set of parameters.
    #[allow(dead_code)]
    pub fn new(
        ed25519_public: VerifyingKey,
        email: String,
        name: String,
        org: Uuid,
        password: HashedPassword,
    ) -> Self {
        let ed25519_public_digest = Sha256Digest::of(ed25519_public.as_bytes());
        let email_digest = Sha256Digest::of(email.as_bytes());
        let name_digest = Sha256Digest::of(name.as_bytes());
        Self {
            ed25519_public,
            ed25519_public_digest,
            email,
            email_digest,
            name,
            name_digest,
            org,
            password,
        }
    }

    /// `test` constructs a `NewUser` suitable for testing.
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
            ),
            signing_key,
        )
    }

    // fn insert(&self) -> User {
    //   actually does the insert, binds the returning columns
    //   to meta::InsertReturning, which will have to be converted
    //   from db implementations and merged with fields from NewUser
    //   to create a User
    // }
}

/// `UserRow` is a flattened struct representing the result of select *.
#[allow(dead_code)]
#[derive(Clone, Debug)]
struct UserRow {
    pub ctime: i64,
    pub ed25519_public: String,
    pub ed25519_public_digest: String,
    pub email: String,
    pub email_digest: String,
    pub id: Uuid,
    pub insert_order: i64,
    pub mtime: i64,
    pub name: String,
    pub name_digest: String,
    pub org: Uuid,
    pub password: String,
    pub role: i64,
    pub schema_version: i64,
    pub signature: String,
    pub status: i64,
}

/// `User` has a name, email, password, org and ed25519 public key from
/// `NewUser`, but with the database-relevant digest and `Meta` fields.
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
    pub meta: Meta,
}

impl User {
    /// `new` constructs a `User` from a `NewUser` (whose fields may come
    /// from a fresh `NewUser::new` or be read back from the database) and
    /// its `Meta`. The digest fields are never recomputed here; they pass
    /// through unchanged from `new_user`.
    #[allow(dead_code)]
    pub fn new(new_user: NewUser, meta: Meta) -> Self {
        let NewUser {
            ed25519_public,
            ed25519_public_digest,
            email,
            email_digest,
            name,
            name_digest,
            org,
            password,
        } = new_user;
        Self {
            ed25519_public,
            ed25519_public_digest,
            email,
            email_digest,
            name,
            name_digest,
            org,
            password,
            meta,
        }
    }
}

impl HasMeta for User {
    fn meta(&self) -> &Meta {
        &self.meta
    }

    fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum UserRowError {
    #[error(transparent)]
    Ed25519PublicDecode(#[from] Ed25519PublicDecodeError),

    #[error(transparent)]
    Password(#[from] PasswordError),

    #[error(transparent)]
    Role(#[from] RoleError),

    #[error(transparent)]
    Sha256Digest(#[from] Sha256DigestDecodeError),

    #[error(transparent)]
    SignatureDecode(#[from] SignatureDecodeError),

    #[error(transparent)]
    Status(#[from] StatusError),
}

impl TryFrom<UserRow> for User {
    type Error = UserRowError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        Ok(Self {
            ed25519_public: decode_ed25519_public(row.ed25519_public.as_str())?,
            ed25519_public_digest: row.ed25519_public_digest.parse()?,
            email: row.email,
            email_digest: row.email_digest.parse()?,
            name: row.name,
            name_digest: row.name_digest.parse()?,
            org: row.org,
            password: row.password.parse()?,
            meta: Meta {
                ctime: row.ctime,
                id: row.id,
                insert_order: row.insert_order,
                mtime: row.mtime,
                role: Role::try_from(row.role)?,
                schema_version: row.schema_version,
                signature: row.signature.parse()?,
                status: Status::try_from(row.status)?,
            },
        })
    }
}
