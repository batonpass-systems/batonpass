//! # Meta
//!
//! `meta` describes metadata common to all models.

use std::str;
use thiserror::Error;
use uuid::Uuid;

use crate::batonpass::model::role::Role;
use crate::batonpass::model::status::Status;

pub const SIGNATURE_LENGTH: usize = 16;

/// `Signature` is a unique stamp from the database, used
/// to identify a unique row version. It is the raw bytes of
/// an md5 hex-encoding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

#[derive(Debug, Error)]
pub enum SignatureDecodeError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("input must be SIGNATURE_LENGTH")]
    Length,
}

impl str::FromStr for Signature {
    type Err = SignatureDecodeError;

    /// `from_str` builds a `Signature` from an md5 hex-encoding
    /// as read from the database.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let bs = hex::decode(raw)?;
        if bs.len() != SIGNATURE_LENGTH {
            return Err(SignatureDecodeError::Length);
        }
        let arr: [u8; SIGNATURE_LENGTH] = bs.try_into().expect("checked length above");
        Ok(Self(arr))
    }
}

/// `Meta` is a set of fields common to all models.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct Meta {
    pub ctime: i64,
    pub id: Uuid,
    pub insert_order: i64,
    pub mtime: i64,
    pub role: Role,
    pub schema_version: i64,
    pub signature: Signature,
    pub status: Status,
}

/// `HasMeta` exposes the `Meta` struct where it is composed.
#[allow(dead_code)]
pub trait HasMeta {
    fn meta(&self) -> &Meta;
    fn meta_mut(&mut self) -> &mut Meta;
}

/// `InsertReturning` is what model insert statements will request in `returning`.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct InsertReturning {
    pub ctime: i64,
    pub insert_order: i64,
    pub mtime: i64,
    pub signature: String,
}
