#!/bin/sh
# Regenerates Swift and Kotlin from the exact locked UniFFI interface.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_binding_output=${1:-"$mowy_repo_root/bindings/generated"}

mkdir -p "$mowy_binding_output"
cd "$mowy_repo_root"
cargo run --locked --offline --quiet --features binding-generator \
  --bin uniffi-bindgen -- generate src/mowy_crypto_core.udl \
  --language swift --out-dir "$mowy_binding_output" --no-format
cargo run --locked --offline --quiet --features binding-generator \
  --bin uniffi-bindgen -- generate src/mowy_crypto_core.udl \
  --language kotlin --out-dir "$mowy_binding_output" --no-format

# UniFFI 0.31.2 emits trailing spaces and extra blank lines. Normalize only
# whitespace so the committed generated boundary passes Git's integrity check
# without depending on host-specific Swift or Kotlin formatters.
find "$mowy_binding_output" -type f -exec perl -0777 -pi -e \
  's/[ \t]+(?=\r?$)//mg; s/(?:\r?\n)+\z/\n/' {} +
