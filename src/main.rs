mod batonpass;

use batonpass::state::State;

#[tokio::main]
async fn main() -> Result<(), batonpass::state::Error> {
    let state = State::unit().await?;
    let _row: (i32,) = sqlx::query_as("select 1")
        .fetch_one(state.random_replica())
        .await
        .expect("select 1");
    println!("Hello, world!");
    Ok(())
}
