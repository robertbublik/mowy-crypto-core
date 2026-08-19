#!/bin/sh
# Runs the complete commit-1 public-core gate.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_cargo_deny_bin=${MOWY_CARGO_DENY_BIN:-cargo-deny}

cd "$mowy_repo_root"
cargo fmt --all -- --check
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
cargo test --locked --offline --all-targets
scripts/build-mobile.sh
scripts/check-source.sh
scripts/check-build-scripts.sh
scripts/check-bindings.sh
scripts/check-sbom.sh
"$mowy_cargo_deny_bin" --version | grep -F 'cargo-deny 0.20.2'
"$mowy_cargo_deny_bin" check bans licenses sources advisories
scripts/check-network-denied.sh
