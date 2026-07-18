//! # Role
//!
//! `role` describes model scope.

#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub enum Role {
    #[default]
    Normal = 1,
    Admin = 2,
    Test = 3,
}
