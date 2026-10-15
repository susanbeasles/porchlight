#!/usr/bin/env bash
# The npm release chain does nothing until a reviewed change enables a real package here.
set -euo pipefail

fail() { echo "::error title=release gate::$1"; exit 1; }

[[ -f "${CONFIG:?}" ]] || fail "$CONFIG is missing"
jq -e 'type == "object"' "$CONFIG" > /dev/null || fail "$CONFIG is not a JSON object"

if [[ "$(jq -r '.enabled' "$CONFIG")" != "true" ]]; then
  echo "::notice title=release gate::npm release is inactive ($CONFIG enabled is not true). Nothing will be built or published."
  echo "enabled=false" >> "$GITHUB_OUTPUT"
  exit 0
fi

field() { jq -r --arg k "$1" '.[$k] // empty | tostring' "$CONFIG"; }
dir=$(field directory); name=$(field name); entry=$(field entry)
out_file=$(field out_file); out_file="${out_file:-dist/index.js}"
budget=$(field max_bundle_bytes); budget="${budget:-0}"

[[ -n "$dir" && -n "$name" && -n "$entry" ]] || fail "enabled, but directory, name and entry must all be set"
[[ "$dir" != /* && "$dir" != *..* ]] || fail "directory must be relative and inside the repository: $dir"
[[ "$budget" =~ ^[0-9]+$ ]] || fail "max_bundle_bytes must be a non-negative integer"
pkg="$dir/package.json"
[[ -f "$pkg" ]] || fail "$pkg does not exist"
[[ -f "$dir/package-lock.json" ]] || fail "$dir/package-lock.json does not exist; the build installs from the lockfile only"
[[ -f "$dir/$entry" ]] || fail "entry $dir/$entry does not exist"

actual=$(jq -r '.name // empty' "$pkg")
[[ "$actual" == "$name" ]] || fail "$pkg is named '$actual', activation names '$name'"
[[ "$(jq -r '.private // false' "$pkg")" != "true" ]] || fail "$pkg is private"
repo_url=$(jq -r 'if (.repository | type) == "object" then .repository.url else .repository end // empty' "$pkg")
want="github.com/${GITHUB_REPOSITORY:?}"
want_rx="${want,,}"; want_rx="${want_rx//./\\.}"
[[ "${repo_url,,}" =~ (^|[/:@])${want_rx}(\.git)?$ ]] \
  || fail "$pkg repository is '$repo_url'; npm provenance needs it to point at $want"
esbuild=$(jq -r '.devDependencies.esbuild // empty' "$pkg")
[[ "$esbuild" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "esbuild must be an exact-version devDependency, got '${esbuild:-none}'"

echo "release gate: active for $name in $dir"
{
  echo "enabled=true"
  echo "directory=$dir"
  echo "name=$name"
  echo "entry=$entry"
  echo "out-file=$out_file"
  echo "max-bundle-bytes=$budget"
} >> "$GITHUB_OUTPUT"
