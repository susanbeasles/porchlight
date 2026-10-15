#!/usr/bin/env bash
# End-to-end test of the release chain against stateful stubs of gh, cosign and npm:
# build output -> cosign-attest -> sealed-release draft/publish -> npm-trusted-publish,
# plus the refusals that keep it sealed. Needs bash, jq, node, tar, sha256sum. Offline.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
actions="$(dirname "$here")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export PATH="$here/stubs:$PATH"

pass=0
ok() { pass=$((pass + 1)); echo "ok $pass - $1"; }
die() { echo "not ok - $1" >&2; exit 1; }
# Last value of key in a GITHUB_OUTPUT file, heredoc values included.
out() {
  awk -v k="$1" '
    d != "" { if ($0 == d) { d = ""; v = buf; buf = "" } else buf = buf $0 "\n"; next }
    index($0, k "<<") == 1 { d = substr($0, length(k) + 3); buf = ""; next }
    index($0, k "=") == 1 { v = substr($0, length(k) + 2) "\n" }
    END { printf "%s", v }' "$2"
}
# Runs a script expecting failure; passes when it fails with the expected message.
refuses() {
  local name="$1" want="$2"; shift 2
  local log="$work/refuse.log"
  if "$@" > "$log" 2>&1; then cat "$log" >&2; die "$name: expected a refusal"; fi
  grep -qF -- "$want" "$log" || { cat "$log" >&2; die "$name: refused, but not with '$want'"; }
  ok "$name"
}

sha=0123456789abcdef0123456789abcdef01234567
other=fedcba9876543210fedcba9876543210fedcba98
export GITHUB_REPOSITORY=o/r GH_REPO=o/r GITHUB_SERVER_URL=https://github.com
export GITHUB_WORKFLOW_REF="o/r/.github/workflows/release.yml@refs/heads/main"
export GITHUB_REF=refs/heads/main GITHUB_SHA=$sha GITHUB_EVENT_NAME=push GITHUB_RUN_ID=7
export RUNNER_TEMP="$work/tmp" GITHUB_STEP_SUMMARY="$work/summary"
export STUB_STATE="$work/state"
mkdir -p "$RUNNER_TEMP/npm-pack" "$STUB_STATE"

# The sealed artifact, as npm-build would leave it.
mkdir -p "$work/pkg/package/dist"
echo '{"name":"@o/example","version":"1.2.3"}' > "$work/pkg/package/package.json"
echo 'console.log(42)' > "$work/pkg/package/dist/index.js"
tgz="$RUNNER_TEMP/npm-pack/o-example-1.2.3.tgz"
tar -czf "$tgz" -C "$work/pkg" package

# --- release side --------------------------------------------------------------------
export GITHUB_OUTPUT="$work/sign.out"
SUBJECTS="$tgz" PREDICATE_TYPE=slsaprovenance1 CHECKSUMS_FILE="$RUNNER_TEMP/npm-pack/SHA256SUMS" \
  bash "$actions/cosign-attest/sign.sh" > /dev/null
files=$(out files "$GITHUB_OUTPUT")
[[ $(grep -c . <<< "$files") == 6 ]] || die "cosign-attest: expected 6 release files, got: $files"
(cd "$RUNNER_TEMP/npm-pack" && sha256sum --strict -c SHA256SUMS > /dev/null) || die "SHA256SUMS does not check"
ok "cosign-attest writes SHA256SUMS and signs it with the tarball (6 files)"

export GITHUB_ACTION_PATH="$actions/sealed-release" TAG=v1.2.3 TARGET=$sha
export GITHUB_OUTPUT="$work/draft.out"
bash "$actions/sealed-release/draft.sh" > /dev/null
[[ "$(out release-id "$GITHUB_OUTPUT")" == 101 ]] || die "draft: no release id"
jq -e '.[0].draft == true' "$STUB_STATE/releases.json" > /dev/null || die "draft: not a draft"
[[ ! -f "$STUB_STATE/tag" ]] || die "draft: tag exists before publish"
ok "draft opens a draft and no tag exists yet"

bash "$actions/sealed-release/draft.sh" > /dev/null
[[ $(jq length "$STUB_STATE/releases.json") == 1 ]] || die "draft: re-run created a second draft"
ok "draft re-run reuses this commit's draft"
TARGET=$other refuses "draft refuses a draft for the same tag at another commit" \
  "is not this run's draft" bash "$actions/sealed-release/draft.sh"

# A stray asset from an earlier failed run, which publish must remove.
echo stray > "$work/stray.txt"; gh release upload v1.2.3 "$work/stray.txt" --clobber
export RELEASE_ID=101 FILES="$files" GITHUB_OUTPUT="$work/publish.out"
touch "$STUB_STATE/tamper_download"
refuses "publish refuses when a downloaded asset differs from the local file" \
  "does not match the local file" bash "$actions/sealed-release/publish.sh"
rm "$STUB_STATE/tamper_download"
jq -e '.[0].draft == true' "$STUB_STATE/releases.json" > /dev/null || die "publish: went live after a failed check"
ok "a failed byte check leaves the release in draft"

bash "$actions/sealed-release/publish.sh" > /dev/null
[[ "$(out url "$GITHUB_OUTPUT")" == "https://github.com/o/r/releases/tag/v1.2.3" ]] || die "publish: no url"
[[ "$(cat "$STUB_STATE/tag")" == "$sha" ]] || die "publish: tag not at target"
[[ ! -f "$STUB_STATE/assets/stray.txt" ]] || die "publish: stray asset kept"
[[ $(ls "$STUB_STATE/assets" | wc -l) == 6 ]] || die "publish: wrong asset count"
ok "publish uploads, removes strays, verifies bytes, goes live with the tag at the commit"

refuses "draft refuses a tag that already exists" "already exists" bash "$actions/sealed-release/draft.sh"

# --- deploy side ---------------------------------------------------------------------
dp="$actions/npm-trusted-publish"
export GITHUB_REF=refs/tags/v1.2.3 GITHUB_EVENT_NAME=workflow_dispatch ACTIONS_ID_TOKEN_REQUEST_URL=https://oidc.invalid
refuses "deploy refuses a static npm token" "NODE_AUTH_TOKEN is set" env NODE_AUTH_TOKEN_SET=true bash "$dp/preflight.sh"
refuses "deploy refuses to run off the tag" "Run at the release tag" env GITHUB_REF=refs/heads/main bash "$dp/preflight.sh"
refuses "deploy refuses without OIDC" "No OIDC token" env -u ACTIONS_ID_TOKEN_REQUEST_URL bash "$dp/preflight.sh"
bash "$dp/preflight.sh" > /dev/null && ok "deploy preflight passes at the tag with OIDC"

export GITHUB_OUTPUT="$work/verify.out"
refuses "deploy refuses a release signed by another workflow" "does not verify" \
  env IDENTITY="https://github.com/o/r/.github/workflows/evil.yml@refs/heads/main" bash "$dp/verify.sh"
refuses "deploy refuses provenance from another commit" "was built from" \
  env GITHUB_SHA=$other bash "$dp/verify.sh"
cp "$STUB_STATE/assets/o-example-1.2.3.tgz" "$work/good.tgz"
echo junk >> "$STUB_STATE/assets/o-example-1.2.3.tgz"
refuses "deploy refuses a tarball that does not match SHA256SUMS" "checksum mismatch" bash "$dp/verify.sh"
cp "$work/good.tgz" "$STUB_STATE/assets/o-example-1.2.3.tgz"

bash "$dp/verify.sh" > /dev/null
[[ "$(out package "$GITHUB_OUTPUT")@$(out version "$GITHUB_OUTPUT")" == "@o/example@1.2.3" ]] || die "verify: outputs"
ok "deploy verifies signature, checksums, provenance commit and version"

export PACKAGE=@o/example VERSION=1.2.3 TARBALL="$(out tarball "$GITHUB_OUTPUT")"
DRY_RUN=true bash "$dp/publish.sh" > /dev/null
[[ ! -f "$STUB_STATE/npm_published_tag" ]] || die "dry run published"
ok "dry run publishes nothing"
bash "$dp/publish.sh" > /dev/null
[[ "$(cat "$STUB_STATE/npm_published_tag")" == latest ]] || die "publish: dist-tag $(cat "$STUB_STATE/npm_published_tag")"
ok "deploy publishes the sealed tarball and checks registry integrity"
rm "$STUB_STATE/npm_published_tag"
bash "$dp/publish.sh" | grep -q "nothing to do" || die "re-run republished"
[[ ! -f "$STUB_STATE/npm_published_tag" ]] || die "re-run called npm publish"
ok "deploy re-run is a no-op when npm already has these bytes"
echo "sha512-other" > "$STUB_STATE/npm/@o_example@1.2.3"
refuses "deploy refuses when npm holds different bytes for the version" "different bytes" bash "$dp/publish.sh"
rm "$STUB_STATE/npm/@o_example@1.2.3"; echo 2.0.0 > "$STUB_STATE/npm_latest"
bash "$dp/publish.sh" > /dev/null
[[ "$(cat "$STUB_STATE/npm_published_tag")" == v1-backport ]] || die "late deploy moved latest"
ok "a late deploy of an older version does not move latest"

echo "# $pass passed"
