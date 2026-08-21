#!/bin/sh
# Rebuilds from vendored inputs while the operating system denies networking.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_network_target=$(mktemp -d "${TMPDIR:-/tmp}/mowy-core-no-network.XXXXXX")

cleanup_mowy_network_target() {
  case "$mowy_network_target" in
    */mowy-core-no-network.*) rm -rf -- "$mowy_network_target" ;;
    *) return 1 ;;
  esac
}
trap cleanup_mowy_network_target EXIT HUP INT TERM

cd "$mowy_repo_root"
case $(uname -s) in
  Darwin)
    sandbox-exec -p '(version 1) (allow default) (deny network*)' \
      env CARGO_TARGET_DIR="$mowy_network_target" \
      cargo test --locked --offline --all-targets
    ;;
  Linux)
    unshare --net env CARGO_TARGET_DIR="$mowy_network_target" \
      cargo test --locked --offline --all-targets
    ;;
  *)
    echo "unsupported operating system for denied-network proof" >&2
    exit 1
    ;;
esac
