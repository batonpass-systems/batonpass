//! # State
//!
//! `state` manages all app state references.

use rand::seq::IndexedRandom;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::time::Duration;
use thiserror::Error;

use crate::batonpass::env as bp_env;

/// `State` manages all app state references.
pub struct State {
    #[allow(unused)]
    pub master: PgPool,
    #[allow(unused)]
    replicas: Vec<PgPool>,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

impl State {
    pub async fn new(level: bp_env::Level) -> Result<Self, Error> {
        match level {
            bp_env::Level::Test => Self::test().await,
            // for when we add other environment levels...
            // _ => panic!("no State constructor"),
        }
    }

    /// `test` provides a State instance for unit testing and development.
    pub async fn test() -> Result<Self, Error> {
        dotenvy::dotenv().ok();

        let pool_options = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .idle_timeout(Duration::from_secs(1))
            .max_connections(100)
            .max_lifetime(None);

        let pg_env_var_url = env::var("POSTGRES_URL").expect("POSTGRES_URL env var");

        let master = pool_options.clone().connect(&pg_env_var_url).await?;
        Ok(Self::for_sqlx_test(master))
    }

    /// `for_sqlx_test` is to be used with the `sqlx::PgPool`
    /// as set up with the #[`sqlx::test`] test header.
    pub fn for_sqlx_test(pool: PgPool) -> Self {
        // Get a pool to the postgres master.
        let master = pool;

        // In the `unit` env, the replicas are just the master.
        let replicas = vec![master.clone()];

        Self { master, replicas }
    }

    /// `random_replica` returns a pool for a random postgres replica.
    pub fn random_replica(&self) -> &sqlx::PgPool {
        let mut rng = rand::rng();
        self.replicas.choose(&mut rng).expect("random replica pool")
    }
}
