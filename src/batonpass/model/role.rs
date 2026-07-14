//! # Role
//!
//! `role` describes model scope.

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Role {
    Normal = 1,
    Admin = 2,
    Test = 3,
}
