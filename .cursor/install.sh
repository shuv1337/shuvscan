#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for shuvscan.
#
# The crate is Rust edition 2024 with rust-version = "1.85", but the base image
# ships an older stable toolchain that cannot parse edition 2024 manifests. This
# installs the toolchains and auxiliary tools the README/CI pipeline require, then
# warms the build cache. It is safe to run repeatedly.
set -euo pipefail

# CI builds/tests on the latest stable toolchain (dtolnay/rust-toolchain@stable).
rustup toolchain install stable --profile minimal --component clippy --component rustfmt
rustup default stable

# CI verifies the declared MSRV with `cargo +1.85 check --locked --all-targets`.
rustup toolchain install 1.85 --profile minimal

# `cargo deny check` is part of the README pre-commit checklist and CI.
if ! command -v cargo-deny >/dev/null 2>&1; then
  cargo install --locked cargo-deny
fi

# AGENTS.md mandates Jujutsu (`jj`) for local version-control work.
if ! command -v jj >/dev/null 2>&1; then
  cargo install --locked jj-cli
fi

# Fetch dependencies and warm the build cache so later commands are fast.
cargo fetch --locked
cargo build --locked
