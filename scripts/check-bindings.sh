#!/bin/sh
# Rejects any drift between the UDL and committed generated bindings.
set -eu

mowy_repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mowy_binding_tmp=$(mktemp -d "${TMPDIR:-/tmp}/mowy-core-bindings.XXXXXX")

cleanup_mowy_binding_tmp() {
  case "$mowy_binding_tmp" in
    */mowy-core-bindings.*) rm -rf -- "$mowy_binding_tmp" ;;
    *) return 1 ;;
  esac
}
trap cleanup_mowy_binding_tmp EXIT HUP INT TERM

"$mowy_repo_root/scripts/generate-bindings.sh" "$mowy_binding_tmp"
diff -ru "$mowy_repo_root/bindings/generated" "$mowy_binding_tmp"
