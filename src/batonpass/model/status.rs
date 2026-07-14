//! # Status
//!
//! `status` describes model status.

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Status {
    Unconfirmed = 1,
    Active = 2,
    Inactive = 3,
}
