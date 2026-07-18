//! # Role
//!
//! `role` describes model scope.

use thiserror::Error;

#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub enum Role {
    #[default]
    Normal = 1,
    Admin = 2,
    Test = 3,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RoleError {
    #[error("invalid Role value: {0}")]
    Invalid(i64),
}

impl TryFrom<i64> for Role {
    type Error = RoleError;

    /// `try_from` builds a `Role` from its database (`i64`) representation.
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Role::Normal),
            2 => Ok(Role::Admin),
            3 => Ok(Role::Test),
            _ => Err(RoleError::Invalid(value)),
        }
    }
}
