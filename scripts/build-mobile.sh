#!/bin/sh
# Builds the release library for the four frozen P2 mobile targets.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_cargo_bin=${MOWY_CARGO_BIN:-cargo}
mowy_android_ndk=${MOWY_ANDROID_NDK_HOME:-${ANDROID_NDK_HOME:-}}

if [ -n "${MOWY_RUSTC_BIN:-}" ]; then
  RUSTC=$MOWY_RUSTC_BIN
  export RUSTC
fi
if [ -n "${MOWY_RUSTDOC_BIN:-}" ]; then
  RUSTDOC=$MOWY_RUSTDOC_BIN
  export RUSTDOC
fi
if [ -z "$mowy_android_ndk" ] && [ -n "${ANDROID_HOME:-}" ]; then
  mowy_android_ndk="$ANDROID_HOME/ndk/27.1.12297006"
fi
if [ ! -d "$mowy_android_ndk/toolchains/llvm/prebuilt" ]; then
  echo "set MOWY_ANDROID_NDK_HOME to Android NDK 27.1.12297006" >&2
  exit 1
fi

case $(uname -s) in
  Darwin) mowy_ndk_host=darwin-x86_64 ;;
  Linux) mowy_ndk_host=linux-x86_64 ;;
  *) echo "unsupported Android NDK host" >&2; exit 1 ;;
esac
mowy_llvm_bin="$mowy_android_ndk/toolchains/llvm/prebuilt/$mowy_ndk_host/bin"

CC_aarch64_linux_android="$mowy_llvm_bin/aarch64-linux-android24-clang"
AR_aarch64_linux_android="$mowy_llvm_bin/llvm-ar"
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$CC_aarch64_linux_android
CC_x86_64_linux_android="$mowy_llvm_bin/x86_64-linux-android24-clang"
AR_x86_64_linux_android="$mowy_llvm_bin/llvm-ar"
CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$CC_x86_64_linux_android
export CC_aarch64_linux_android AR_aarch64_linux_android
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER
export CC_x86_64_linux_android AR_x86_64_linux_android
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER

cd "$mowy_repo_root"
"$mowy_cargo_bin" build --locked --offline --release --lib \
  --target aarch64-apple-ios
"$mowy_cargo_bin" build --locked --offline --release --lib \
  --target aarch64-apple-ios-sim
"$mowy_cargo_bin" build --locked --offline --release --lib \
  --target aarch64-linux-android
"$mowy_cargo_bin" build --locked --offline --release --lib \
  --target x86_64-linux-android
