#!/bin/sh
# Verifies the immutable crate checksum and its independently signed source.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_rsign_bin=${MOWY_RSIGN_BIN:-rsign}
mowy_sodium_public_key=RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3

cd "$mowy_repo_root"
shasum -a 256 -c supply-chain/libsodium-source.sha256
awk '
  $0 == "name = \"libsodium-sys-stable\"" { in_package = 1 }
  in_package && $0 == "checksum = \"72b04bf6da2c98b727af37ab62cb505f4d751b975b034a9b9ad491d333b0564e\"" { found = 1; exit }
  in_package && /^\[\[package\]\]$/ { exit }
  END { exit(found ? 0 : 1) }
' Cargo.lock
"$mowy_rsign_bin" verify \
  --public-key-string "$mowy_sodium_public_key" \
  --sig-file vendor/libsodium-sys-stable/LATEST.tar.gz.minisig \
  vendor/libsodium-sys-stable/LATEST.tar.gz
