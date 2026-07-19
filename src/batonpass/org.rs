//! # Org
//!
//! `org` is a collection of users in batonpass.

use std::convert::TryFrom;
use thiserror::Error;
use uuid::Uuid;

use crate::batonpass::crypt::rand_string;
use crate::batonpass::crypt::signature::SignatureDecodeError;
use crate::batonpass::model::meta::{HasMeta, Meta};
use crate::batonpass::model::role::{Role, RoleError};
use crate::batonpass::model::status::{Status, StatusError};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct NewOrg {
    name: String,
    owner: Uuid,
}

impl NewOrg {
    #[allow(dead_code)]
    pub fn new(name: String, owner: Uuid) -> Self {
        Self { name, owner }
    }

    /// `test` constructs a `NewOrg` suitable for testing.
    #[allow(dead_code)]
    pub fn test() -> Self {
        Self::new(rand_string(), Uuid::now_v7())
    }
}

/// `OrgRow` is a flattened struct representing the result of select *.
#[allow(dead_code)]
#[derive(Clone, Debug)]
struct OrgRow {
    pub ctime: i64,
    pub id: Uuid,
    pub insert_order: i64,
    pub mtime: i64,
    pub name: String,
    pub owner: Uuid,
    pub role: i64,
    pub schema_version: i64,
    pub signature: String,
    pub status: i64,
}

/// `Org` has a name, owner from `NewOrg`, but with the database-relevant
/// `Meta` fields.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Org {
    name: String,
    owner: Uuid,
    meta: Meta,
}

impl HasMeta for Org {
    fn meta(&self) -> &Meta {
        &self.meta
    }

    fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum OrgRowError {
    #[error(transparent)]
    Role(#[from] RoleError),

    #[error(transparent)]
    SignatureDecode(#[from] SignatureDecodeError),

    #[error(transparent)]
    Status(#[from] StatusError),
}

impl TryFrom<OrgRow> for Org {
    type Error = OrgRowError;

    fn try_from(row: OrgRow) -> Result<Self, Self::Error> {
        Ok(Self {
            name: row.name,
            owner: row.owner,
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
