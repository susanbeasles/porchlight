#!/usr/bin/env bash
# Fails unless the handoff directory holds exactly the expected files and the tarball is
# byte-identical to what the build job produced.
set -euo pipefail

fail() { echo "::error title=artifact check::$1"; exit 1; }

[[ "${SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || fail "sha256 must be 64 hex characters"
[[ "${TARBALL:-}" =~ ^[A-Za-z0-9._-]+\.tgz$ ]] || fail "tarball must be a plain .tgz file name, got '${TARBALL:-}'"
[[ -d "${DIR:-}" ]] || fail "no such directory: ${DIR:-}"
dir="$(cd "$DIR" && pwd)"

want=("$TARBALL")
if [[ "${SIGNED:-false}" == "true" ]]; then
  want+=(SHA256SUMS "$TARBALL.sigstore.json" "$TARBALL.intoto.sigstore.json"
         SHA256SUMS.sigstore.json SHA256SUMS.intoto.sigstore.json)
fi
have=$(cd "$dir" && find . -mindepth 1 -printf '%P\n' | sort)
expected=$(printf '%s\n' "${want[@]}" | sort)
[[ "$have" == "$expected" ]] || fail "handoff holds [$(echo $have)], expected exactly [$(echo $expected)]"

actual=$(sha256sum "$dir/$TARBALL" | cut -d' ' -f1)
[[ "$actual" == "$SHA256" ]] || fail "$TARBALL is $actual, the build recorded $SHA256"

if [[ "${SIGNED:-false}" == "true" ]]; then
  [[ "$(cat "$dir/SHA256SUMS")" == "$SHA256  $TARBALL" ]] \
    || fail "SHA256SUMS must list exactly '$SHA256  $TARBALL'"
fi

delim="EOF_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
{
  echo "files<<$delim"
  for f in "${want[@]}"; do echo "$dir/$f"; done
  echo "$delim"
} >> "${GITHUB_OUTPUT:?}"
echo "artifact check: $TARBALL $actual, ${#want[@]} files as expected"
