#!/usr/bin/env bash
# One tree-shaken, minified bundle from the package's own pinned esbuild.
set -euo pipefail

fail() { echo "::error title=npm build::$1"; exit 1; }

[[ -x node_modules/.bin/esbuild ]] || fail "esbuild is not in devDependencies. Pin it there so the lockfile fixes its version and integrity."
[[ -f "$ENTRY" ]] || fail "entry $ENTRY not found"

rm -rf "$(dirname "$OUT_FILE")"
mkdir -p "$(dirname "$OUT_FILE")"
meta="$RUNNER_TEMP/esbuild-meta.json"
node_modules/.bin/esbuild "$ENTRY" \
  --bundle --minify --tree-shaking=true \
  --format="$FORMAT" --platform="$PLATFORM" --target="$TARGET" \
  --packages=external --legal-comments=none --log-level=warning \
  --metafile="$meta" --outfile="$OUT_FILE"

bytes=$(wc -c < "$OUT_FILE" | tr -d ' ')
echo "bytes=$bytes" >> "$GITHUB_OUTPUT"
{
  echo "### Bundle"
  echo "\`$OUT_FILE\`: $bytes bytes (minified, tree-shaken, dependencies external)"
} >> "$GITHUB_STEP_SUMMARY"
if [[ "$MAX_BYTES" != "0" ]] && (( bytes > MAX_BYTES )); then
  fail "bundle is $bytes bytes, over the $MAX_BYTES budget"
fi
echo "bundle: $OUT_FILE $bytes bytes"
