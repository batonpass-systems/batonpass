//! # Status
//!
//! `status` describes model status.

use thiserror::Error;

#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub enum Status {
    Unconfirmed = 1,
    #[default]
    Active = 2,
    Inactive = 3,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StatusError {
    #[error("invalid Status value: {0}")]
    Invalid(i64),
}

impl TryFrom<i64> for Status {
    type Error = StatusError;

    /// `try_from` builds a `Status` from its database (`i64`) representation.
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Status::Unconfirmed),
            2 => Ok(Status::Active),
            3 => Ok(Status::Inactive),
            _ => Err(StatusError::Invalid(value)),
        }
    }
}
