//! # Meta
//!
//! `meta` describes metadata common to all models.

use crate::batonpass::model::role::Role;
use crate::batonpass::model::status::Status;
use uuid::Uuid;

/// `Signature` is a unique stamp from the database, used
/// to identify a unique
pub type Signature = [u8; 32];

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
#[derive(Copy, Clone, Debug)]
pub struct InsertReturning {
    pub ctime: i64,
    pub insert_order: i64,
    pub mtime: i64,
    pub signature: Signature,
}
