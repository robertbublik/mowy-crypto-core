#!/bin/sh
# Rejects an unreviewed build script entering the vendored graph.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_build_list=$(mktemp "${TMPDIR:-/tmp}/mowy-core-build-scripts.XXXXXX")

cleanup_mowy_build_list() {
  case "$mowy_build_list" in
    */mowy-core-build-scripts.*) rm -f -- "$mowy_build_list" ;;
    *) return 1 ;;
  esac
}
trap cleanup_mowy_build_list EXIT HUP INT TERM

find "$mowy_repo_root/vendor" -mindepth 2 -maxdepth 2 -name build.rs -print \
  | sed "s#^$mowy_repo_root/vendor/##; s#/build.rs\$##" \
  | sort > "$mowy_build_list"
diff -u "$mowy_repo_root/supply-chain/build-scripts.txt" "$mowy_build_list"
