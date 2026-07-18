//! # Status
//!
//! `status` describes model status.

#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub enum Status {
    Unconfirmed = 1,
    #[default]
    Active = 2,
    Inactive = 3,
}
