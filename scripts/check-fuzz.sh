#!/bin/sh
# Runs both pinned cargo-fuzz targets against disposable corpus workspaces.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_cargo_fuzz_bin=${MOWY_CARGO_FUZZ_BIN:-cargo-fuzz}
mowy_fuzz_runs=${MOWY_FUZZ_RUNS:-10000}
mowy_fuzz_sanitizer=${MOWY_FUZZ_SANITIZER:-none}
mowy_fuzz_work=$(mktemp -d "${TMPDIR:-/tmp}/mowy-core-fuzz.XXXXXX")

cleanup_mowy_fuzz_work() {
  case "$mowy_fuzz_work" in
    */mowy-core-fuzz.*) rm -rf -- "$mowy_fuzz_work" ;;
    *) return 1 ;;
  esac
}
trap cleanup_mowy_fuzz_work EXIT HUP INT TERM

mkdir -p "$mowy_fuzz_work/sealed-manifest" "$mowy_fuzz_work/attachment-envelope"
cp "$mowy_repo_root"/fuzz/corpus/sealed_manifest/* "$mowy_fuzz_work/sealed-manifest/"
cp "$mowy_repo_root"/fuzz/corpus/attachment_envelope/* "$mowy_fuzz_work/attachment-envelope/"

cd "$mowy_repo_root"
"$mowy_cargo_fuzz_bin" run --sanitizer "$mowy_fuzz_sanitizer" \
  sealed_manifest "$mowy_fuzz_work/sealed-manifest" -- \
  -runs="$mowy_fuzz_runs" -max_len=1024
"$mowy_cargo_fuzz_bin" run --sanitizer "$mowy_fuzz_sanitizer" \
  attachment_envelope "$mowy_fuzz_work/attachment-envelope" -- \
  -runs="$mowy_fuzz_runs" -max_len=4096
