#!/usr/bin/env bash
# Packs once and refuses a package that ships anything beyond the bundle and its metadata.
# The same tarball is what gets published, released and signed.
set -euo pipefail

fail() { echo "::error title=npm trusted publish::$1"; exit 1; }

out_dir="$RUNNER_TEMP/npm-pack"
rm -rf "$out_dir" && mkdir -p "$out_dir"
json=$(npm pack --json --pack-destination "$out_dir")
files=$(node -e 'const p=JSON.parse(process.argv[1])[0]; for (const f of p.files) console.log(f.path)' "$json")
name=$(node -e 'console.log(JSON.parse(process.argv[1])[0].filename)' "$json")

out_dir_rel=$(dirname "$OUT_FILE")
unexpected=$(printf '%s\n' "$files" | grep -vE "^(${out_dir_rel//./\\.}/|package\.json$|README(\.[a-z]+)?$|LICENSE(\.[a-z]+)?$|CHANGELOG(\.[a-z]+)?$)" || true)
if [[ -n "$unexpected" ]]; then
  echo "$unexpected" | sed 's/^/  unexpected: /'
  fail "package contains files outside $out_dir_rel/ and metadata; restrict package.json \"files\""
fi
printf '%s\n' "$files" | grep -qxF "$OUT_FILE" || fail "package does not contain $OUT_FILE"

tarball="$out_dir/$name"
echo "tarball=$tarball" >> "$GITHUB_OUTPUT"
echo "pack: $name"; printf '%s\n' "$files" | sed 's/^/  /'
