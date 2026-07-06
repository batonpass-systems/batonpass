//! # State
//!
//! `state` manages all app state references.

use rand::seq::IndexedRandom;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::time::Duration;
use thiserror::Error;

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
    /// `unit` provides a State instance for unit testing and development.
    pub async fn unit() -> Result<State, Error> {
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
    pub fn for_sqlx_test(pool: PgPool) -> State {
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
