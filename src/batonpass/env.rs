//! # Env
//!
//! `env` provides environment detection support.
use std::fmt;

/// `Level` describes the run level.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Level {
    #[default]
    Test,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
