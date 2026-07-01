set shell := ["bash", "-c"]
set dotenv-load := false

# for testing purposes only

export PGHOST := 'localhost'
export PGDATABASE := 'batonpass'
export PGUSERNAME := 'batonpass'
export PGPASSWORD := 'batonpass'
export POSTGRES_URL := 'postgres://batonpass:batonpass@localhost:5432/batonpass'

default:
    @just --list

all:
    just --justfile {{ justfile() }} build pedantic test

build:
    cargo build

clippy:
    cargo clippy --all -- -D warnings

pedantic:
    cargo clippy --all -- -D warnings -D clippy::pedantic

run:
    cargo run

debug:
    env RUST_LOG=info cargo run

test:
    env RUST_LOG=warn cargo test

update:
    cargo update
