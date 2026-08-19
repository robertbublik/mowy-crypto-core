#!/bin/sh
# Runs the complete public-core gate for the implemented P2 slices.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_cargo_bin=${MOWY_CARGO_BIN:-cargo}
mowy_cargo_deny_bin=${MOWY_CARGO_DENY_BIN:-cargo-deny}

cd "$mowy_repo_root"
"$mowy_cargo_bin" fmt --all -- --check
"$mowy_cargo_bin" clippy --locked --offline --all-targets --all-features -- -D warnings
"$mowy_cargo_bin" test --locked --offline --all-targets
scripts/build-mobile.sh
scripts/check-source.sh
scripts/check-build-scripts.sh
scripts/check-bindings.sh
scripts/check-sbom.sh
scripts/check-platform-key-storage.sh
"$mowy_cargo_deny_bin" --version | grep -F 'cargo-deny 0.20.2'
"$mowy_cargo_deny_bin" check bans licenses sources advisories
scripts/check-network-denied.sh
