//! `VersionKeyMap` tracks encryption keys by version.
use std::collections::HashMap;
use uuid::Uuid;

use super::key::Key;
use crate::batonpass::env;

#[derive(Clone, Debug)]
pub struct VersionKeyMap {
    pub keymap: HashMap<Uuid, Key>,
    pub current_version: Uuid,
}

impl VersionKeyMap {
    pub fn new(level: env::Level) -> Self {
        match level {
            env::Level::Test => Self::test(),
            // for when we add other environment levels...
            // _ => panic!("no VersionKeyMap constructor"),
        }
    }

    /// `test` returns a `VersionKeyMap` instance for unit tests.
    pub fn test() -> Self {
        let mut m: HashMap<Uuid, Key> = HashMap::new();
        // Insert a random key, which is not going to be set as current.
        _ = m.insert(Uuid::now_v7(), Key::rand());
        // Insert a random key, which is the current key.
        let current_version = Uuid::now_v7();
        _ = m.insert(current_version, Key::rand());
        Self {
            keymap: m,
            current_version,
        }
    }

    /// `get` performs a `get` on the interior `HashMap`.
    pub fn get(&self, version: Uuid) -> Option<&Key> {
        self.keymap.get(&version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn versionkeymap_test() {
        let vk = VersionKeyMap::new(env::Level::Test);
        assert!(vk.get(vk.current_version).is_some());
    }
}
