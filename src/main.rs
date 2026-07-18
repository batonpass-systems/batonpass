mod batonpass;

use crate::batonpass::env as bp_env;
use batonpass::state::State;
use tracing::info;

#[allow(dead_code)]
struct Ping {
    one: i32,
}

#[tokio::main]
async fn main() -> Result<(), batonpass::state::Error> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let state = State::new(bp_env::Level::Test).await?;
    let _row = sqlx::query_as!(Ping, r#"select 1 as "one!""#)
        .fetch_one(state.random_replica())
        .await
        .expect("select 1");
    info!("main");
    Ok(())
}
