set shell := ["bash", "-c"]
set dotenv-filename := ".env"

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
    env RUST_LOG=info cargo test

test-verbose:
    env RUST_LOG=info cargo test -- --nocapture

update:
    cargo update
