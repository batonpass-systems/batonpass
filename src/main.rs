mod batonpass;

use batonpass::state::State;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), batonpass::state::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let state = State::unit().await?;
    let _row: (i32,) = sqlx::query_as("select 1")
        .fetch_one(state.random_replica())
        .await
        .expect("select 1");
    info!("main");
    Ok(())
}
