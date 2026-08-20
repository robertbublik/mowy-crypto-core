#!/bin/sh
# Confirms the committed SBOM covers the exact approved direct dependency pins.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_bom="$mowy_repo_root/supply-chain/bom.cdx.json"
mowy_cyclonedx_bin=${MOWY_CARGO_CYCLONEDX_BIN:-cargo-cyclonedx}
mowy_generated_bom="$mowy_repo_root/mowy-crypto-core-check.json"
mowy_raw_bom="$mowy_repo_root/mowy-crypto-core-check.raw.json"
mowy_root_ref="path+file://$mowy_repo_root#mowy-crypto-core@0.1.0"
mowy_stable_ref='pkg:cargo/mowy-crypto-core@0.1.0'

cleanup_mowy_generated_bom() {
  case "$mowy_generated_bom" in
    */mowy-crypto-core-check.json) rm -f -- "$mowy_generated_bom" ;;
    *) return 1 ;;
  esac
  case "$mowy_raw_bom" in
    */mowy-crypto-core-check.raw.json) rm -f -- "$mowy_raw_bom" ;;
    *) return 1 ;;
  esac
}
trap cleanup_mowy_generated_bom EXIT HUP INT TERM

jq -e '
  .bomFormat == "CycloneDX" and
  .specVersion == "1.5" and
  ([.components[] | select((.licenses // []) | length == 0)] | length == 0)
' "$mowy_bom" >/dev/null

for mowy_pin in \
  'libsodium-rs=0.2.4' \
  'libsodium-sys-stable=1.24.0' \
  'uniffi=0.31.2' \
  'rusqlite=0.40.1' \
  'libsqlite3-sys=0.38.1' \
  'zeroize=1.9.0'
do
  mowy_name=${mowy_pin%%=*}
  mowy_version=${mowy_pin#*=}
  jq -e --arg name "$mowy_name" --arg version "$mowy_version" \
    'any(.components[]; .name == $name and .version == $version)' \
    "$mowy_bom" >/dev/null
done

"$mowy_cyclonedx_bin" cyclonedx --version | grep -F '0.5.9'
if [ -e "$mowy_generated_bom" ] || [ -e "$mowy_raw_bom" ]; then
  echo "refusing to overwrite SBOM check output" >&2
  exit 1
fi
(
  cd "$mowy_repo_root"
  SOURCE_DATE_EPOCH=1787097600 "$mowy_cyclonedx_bin" cyclonedx \
    --format json --spec-version 1.5 --all-features --target all \
    --override-filename mowy-crypto-core-check.raw
)
jq --arg root_ref "$mowy_root_ref" --arg stable_ref "$mowy_stable_ref" '
  walk(
    if type == "string" and startswith($root_ref) then
      $stable_ref + .[($root_ref | length):]
    else
      .
    end
  )
' "$mowy_raw_bom" >"$mowy_generated_bom"
diff -u "$mowy_bom" "$mowy_generated_bom"
