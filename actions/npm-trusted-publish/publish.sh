#!/usr/bin/env bash
# Publishes the verified tarball as is, then confirms the registry holds those exact bytes.
# Safe to re-run: a version already on npm is checked, not republished.
set -euo pipefail

fail() { echo "::error title=npm trusted publish::$1"; exit 1; }

spec="$PACKAGE@$VERSION"
local_integrity="sha512-$(node -e 'process.stdout.write(require("crypto").createHash("sha512").update(require("fs").readFileSync(process.argv[1])).digest("base64"))' "$TARBALL")"

# Integrity of a version on npm, empty if it is not there. Any error but 404 fails.
registry_integrity() {
  local out
  if out=$(npm view "$spec" dist.integrity 2>&1); then
    echo "$out"
  elif [[ "$out" == *E404* ]]; then
    echo ""
  else
    fail "npm view $spec failed: $out"
  fi
}

existing=$(registry_integrity)
if [[ -n "$existing" ]]; then
  [[ "$existing" == "$local_integrity" ]] || fail "$spec is already on npm with different bytes ($existing)"
  echo "publish: $spec is already on npm with these bytes; nothing to do"
  exit 0
fi

# Never move "latest" backwards when an older release is deployed late.
latest=$(npm view "$PACKAGE" dist-tags.latest 2>/dev/null || true)
dist_tag=latest
if [[ -n "$latest" ]] && [[ "$(printf '%s\n%s\n' "$latest" "$VERSION" | sort -V | tail -1)" != "$VERSION" ]]; then
  dist_tag="v${VERSION%%.*}-backport"
fi

if [[ "${DRY_RUN:-false}" == "true" ]]; then
  echo "publish: dry run; would publish $spec with dist-tag $dist_tag"
  exit 0
fi

# No NODE_AUTH_TOKEN: npm exchanges the job's OIDC token for a short-lived publish
# credential and attaches a Sigstore provenance attestation naming this run and commit.
npm publish "$TARBALL" --provenance --access public --tag "$dist_tag"

for attempt in 1 2 3 4 5 6; do
  existing=$(registry_integrity)
  [[ -n "$existing" ]] && break
  sleep $((attempt * 5))
done
[[ "$existing" == "$local_integrity" ]] || fail "registry integrity for $spec is '${existing:-missing}', expected $local_integrity"
echo "publish: $spec live on npm ($dist_tag), integrity matches the sealed tarball"
{
  echo "### npm"
  echo
  echo "\`$spec\` published with dist-tag \`$dist_tag\`, integrity \`$local_integrity\`"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
