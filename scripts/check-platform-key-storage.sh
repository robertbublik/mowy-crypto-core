#!/bin/sh
# Compiles both protected-storage adapters and runs their host-safe tests.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_gradle_bin=${MOWY_GRADLE_BIN:-gradle}
mowy_android_home=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
mowy_iphoneos_sdk=$(xcrun --sdk iphoneos --show-sdk-path)
mowy_swift_scratch=$(mktemp -d "${TMPDIR:-/tmp}/mowy-p2-swift-tests.XXXXXX")
trap 'rm -rf "$mowy_swift_scratch"' EXIT HUP INT TERM

if [ -z "$mowy_android_home" ] || [ ! -d "$mowy_android_home/platforms/android-36" ]; then
  echo "set ANDROID_HOME to an SDK containing platform 36" >&2
  exit 1
fi
"$mowy_gradle_bin" --version | grep -F 'Gradle 8.14.3'

cd "$mowy_repo_root"
xcrun --sdk iphoneos swiftc -swift-version 5 -parse-as-library -typecheck \
  -target arm64-apple-ios15.1 -sdk "$mowy_iphoneos_sdk" \
  platform/ios/MowyProtectedKeyStore.swift
swift test --package-path platform/ios --scratch-path "$mowy_swift_scratch"
ANDROID_HOME="$mowy_android_home" ANDROID_SDK_ROOT="$mowy_android_home" \
  "$mowy_gradle_bin" -p platform/android --offline --no-daemon \
  :key-storage:lintDebug :key-storage:testDebugUnitTest
