#!/usr/bin/env bash
# The release chain end to end, job by job, against stateful stubs of gh, cosign and npm:
#   gate -> build handoff -> sign -> signed handoff -> verify-only -> draft -> publish
#   -> deploy (preflight, verify, publish)
# plus the refusals that keep it sealed. Needs bash, jq, node, tar, sha256sum. Offline.
#
# The stubs prove the scripts' logic and their failure handling. They do not prove real
# cosign, GitHub or npm behavior; those are the live acceptance checks in ADR-0008.
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
# Runs a command expecting failure; passes when it fails with the expected message.
refuses() {
  # Distinct names: bash locals are dynamically scoped and would shadow the commands' globals.
  local _case="$1" _want="$2"; shift 2
  local _log="$work/refuse.log"
  if "$@" > "$_log" 2>&1; then cat "$_log" >&2; die "$_case: expected a refusal"; fi
  grep -qF -- "$_want" "$_log" || { cat "$_log" >&2; die "$_case: refused, but not with '$_want'"; }
  ok "$_case"
}

sha=0123456789abcdef0123456789abcdef01234567
other=fedcba9876543210fedcba9876543210fedcba98
export GITHUB_REPOSITORY=o/r GH_REPO=o/r GITHUB_SERVER_URL=https://github.com
export GITHUB_WORKFLOW_REF="o/r/.github/workflows/release.yml@refs/heads/main"
export GITHUB_REF=refs/heads/main GITHUB_SHA=$sha GITHUB_EVENT_NAME=push GITHUB_RUN_ID=7
export RUNNER_TEMP="$work/tmp" GITHUB_STEP_SUMMARY="$work/summary"
export STUB_STATE="$work/state"
mkdir -p "$RUNNER_TEMP" "$STUB_STATE"

# --- gate: release/npm.json is the only switch ----------------------------------------
repo="$work/repo"; mkdir -p "$repo/release" "$repo/packages/ex/src"
cp "$actions/../release/npm.json" "$repo/release/npm.json"
export GITHUB_OUTPUT="$work/gate.out"
(cd "$repo" && CONFIG=release/npm.json bash "$actions/release-gate/gate.sh") > /dev/null
[[ "$(out enabled "$GITHUB_OUTPUT")" == false && -z "$(out name "$GITHUB_OUTPUT")" ]] \
  || die "gate: the committed release/npm.json must be inactive"
ok "the committed activation file is inactive: the chain stops at the gate"

activate() { # name dir entry
  jq -n --arg n "$1" --arg d "$2" --arg e "$3" \
    '{enabled: true, directory: $d, name: $n, entry: $e, out_file: "dist/index.js", max_bundle_bytes: 0}' \
    > "$repo/release/npm.json"
}
pkg_json() { # name private repository esbuild
  jq -n --arg n "$1" --argjson p "$2" --arg r "$3" --arg e "$4" \
    '{name: $n, version: "1.2.3", private: $p, repository: {type: "git", url: $r}, devDependencies: {esbuild: $e}}' \
    > "$repo/packages/ex/package.json"
}
gate() { (cd "$repo" && CONFIG=release/npm.json bash "$actions/release-gate/gate.sh"); }
echo '{}' > "$repo/packages/ex/package-lock.json"; echo 'export {}' > "$repo/packages/ex/src/index.ts"
pkg_json "@o/example" false "git+https://github.com/o/r.git" "0.25.10"

activate "@o/other" packages/ex src/index.ts
refuses "gate refuses a package whose name differs from the activation" "activation names" gate
activate "@o/example" ../outside src/index.ts
refuses "gate refuses a directory outside the repository" "inside the repository" gate
activate "@o/example" packages/ex src/index.ts
pkg_json "@o/example" true "git+https://github.com/o/r.git" "0.25.10"
refuses "gate refuses a private package" "is private" gate
pkg_json "@o/example" false "git+https://github.com/someone/else.git" "0.25.10"
refuses "gate refuses a repository other than this one" "needs it to point at" gate
pkg_json "@o/example" false "git+https://github.com/oxr.git" "0.25.10"
refuses "gate does not treat '.' in the repository as a wildcard" "needs it to point at" gate
pkg_json "@o/example" false "git+https://github.com/o/r.git" "^0.25.0"
refuses "gate refuses a floating esbuild range" "exact-version" gate
pkg_json "@o/example" false "git+https://github.com/o/r.git" "0.25.10"
rm "$repo/packages/ex/package-lock.json"
refuses "gate refuses a package without a lockfile" "package-lock.json does not exist" gate
echo '{}' > "$repo/packages/ex/package-lock.json"
refuses "gate refuses activation without independent artifact identity" "independently reviewed artifact identity" gate
# A real, isolated Git fixture provides the independently reviewed package tree.
git -C "$repo" init -q
git -C "$repo" add packages
fixture_tree=$(git -C "$repo" write-tree)
fixture_commit=$(printf 'fixture\n' | GIT_AUTHOR_NAME=Fixture GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_NAME=Fixture GIT_COMMITTER_EMAIL=fixture@example.invalid git -C "$repo" commit-tree "$fixture_tree")
git -C "$repo" update-ref HEAD "$fixture_commit"
source_tree=$(git -C "$repo" rev-parse HEAD:packages/ex)
lock_digest=$(sha256sum "$repo/packages/ex/package-lock.json" | cut -d' ' -f1)
jq --arg tree "$source_tree" --arg lock "$lock_digest" '.artifact_identity = {filename: "o-example-1.2.3.tgz", sha256: ("0" * 64), source_tree: $tree, package_lock_sha256: $lock}' "$repo/release/npm.json" > "$work/activation.json"
cp "$work/activation.json" "$repo/release/npm.json"
gate > /dev/null
[[ "$(out enabled "$GITHUB_OUTPUT")" == true && "$(out name "$GITHUB_OUTPUT")" == "@o/example" \
   && "$(out directory "$GITHUB_OUTPUT")" == packages/ex ]] || die "gate: active outputs"
ok "gate passes a deliberately activated, valid package"

# --- build handoff: the tarball npm-build packed, and the digest it recorded -----------
mkdir -p "$work/pkg/package/dist"
echo '{"name":"@o/example","version":"1.2.3"}' > "$work/pkg/package/package.json"
echo 'console.log(42)' > "$work/pkg/package/dist/index.js"
tgz=o-example-1.2.3.tgz
sealed="$RUNNER_TEMP/sealed"; mkdir -p "$sealed"
tar -czf "$sealed/$tgz" -C "$work/pkg" package
digest=$(sha256sum "$sealed/$tgz" | cut -d' ' -f1)
handoff() { DIR="$sealed" TARBALL="$tgz" SHA256="$1" SIGNED="$2" bash "$actions/artifact-check/check.sh"; }

export GITHUB_OUTPUT="$work/check.out"
refuses "sign refuses a tarball whose digest differs from the build's" "the build recorded" \
  handoff "$(printf '0%.0s' {1..64})" false
touch "$sealed/extra.js"
refuses "sign refuses a handoff carrying an extra file" "expected exactly" handoff "$digest" false
rm "$sealed/extra.js"
handoff "$digest" false > /dev/null
ok "the build handoff is exactly one tarball at the recorded digest"

# --- sign (id-token only) --------------------------------------------------------------
export GITHUB_OUTPUT="$work/sign.out"
SUBJECTS="$sealed/$tgz" PREDICATE_TYPE=slsaprovenance1 CHECKSUMS_FILE="$sealed/SHA256SUMS" \
  bash "$actions/cosign-attest/sign.sh" > /dev/null
[[ $(out files "$GITHUB_OUTPUT" | grep -c .) == 6 ]] || die "sign: expected 6 files"
ok "sign writes SHA256SUMS and signs and attests it with the tarball"

# --- release (contents: write only) -----------------------------------------------------
export GITHUB_OUTPUT="$work/check2.out"
handoff "$digest" true > /dev/null
files=$(out files "$GITHUB_OUTPUT")
cp "$sealed/SHA256SUMS" "$work/sums.bak"
echo "$digest  other.tgz" >> "$sealed/SHA256SUMS"
refuses "release refuses a SHA256SUMS listing anything else" "must list exactly" handoff "$digest" true
cp "$work/sums.bak" "$sealed/SHA256SUMS"
ok "the signed handoff is exactly the six expected files"

verify_only() { SUBJECTS="$sealed/$tgz"$'\n'"$sealed/SHA256SUMS" PREDICATE_TYPE=slsaprovenance1 \
  VERIFY_ONLY=true bash "$actions/cosign-attest/sign.sh"; }
export GITHUB_OUTPUT="$work/verify-only.out"
verify_only > /dev/null
[[ "$(out identity "$GITHUB_OUTPUT")" == "https://github.com/$GITHUB_WORKFLOW_REF" ]] || die "verify-only identity"
ok "release verifies every bundle before anything becomes public"
cp "$sealed/$tgz.sigstore.json" "$work/sig.bak"
jq '.sha = "0"' "$work/sig.bak" > "$sealed/$tgz.sigstore.json"
refuses "a bad signature bundle is not masked by a good attestation" "do not verify" verify_only
cp "$work/sig.bak" "$sealed/$tgz.sigstore.json"
verify_as_other() { GITHUB_WORKFLOW_REF="o/r/.github/workflows/other.yml@refs/heads/main" verify_only; }
verify_with_checksums() { CHECKSUMS_FILE="$sealed/x" verify_only; }
refuses "verify-only refuses a signer other than this workflow" "do not verify" verify_as_other
refuses "verify-only refuses to also write checksums" "checksums-file is for signing" verify_with_checksums
[[ ! -e "$sealed/x" ]] || die "verify-only wrote a checksums file"

export GITHUB_ACTION_PATH="$actions/sealed-release" TAG=v1.2.3 TARGET=$sha
export GITHUB_OUTPUT="$work/draft.out"
bash "$actions/sealed-release/draft.sh" > /dev/null
[[ "$(out release-id "$GITHUB_OUTPUT")" == 101 ]] || die "draft: no release id"
[[ ! -f "$STUB_STATE/tag" ]] || die "draft: tag exists before publish"
ok "draft opens a draft and no tag exists yet"
bash "$actions/sealed-release/draft.sh" > /dev/null
[[ $(jq length "$STUB_STATE/releases.json") == 1 ]] || die "draft: re-run created a second draft"
ok "draft re-run reuses this commit's draft"
TARGET=$other refuses "draft refuses a draft for the same tag at another commit" \
  "is not this run's draft" bash "$actions/sealed-release/draft.sh"

echo stray > "$work/stray.txt"; gh release upload v1.2.3 "$work/stray.txt" --clobber
export RELEASE_ID=101 FILES="$files" GITHUB_OUTPUT="$work/publish.out"
touch "$STUB_STATE/tamper_download"
refuses "publish refuses when a read-back asset differs from the local file" \
  "does not match the local file" bash "$actions/sealed-release/publish.sh"
rm "$STUB_STATE/tamper_download"
jq -e '.[0].draft == true' "$STUB_STATE/releases.json" > /dev/null || die "publish: went live after a failed check"
ok "a failed byte check leaves the release in draft"
bash "$actions/sealed-release/publish.sh" > /dev/null
[[ "$(cat "$STUB_STATE/tag")" == "$sha" ]] || die "publish: tag not at target"
[[ ! -f "$STUB_STATE/assets/stray.txt" ]] || die "publish: stray asset kept"
[[ $(ls "$STUB_STATE/assets" | wc -l) == 6 ]] || die "publish: wrong asset count"
ok "publish uploads, removes strays, reads every byte back, goes live with the tag at the commit"
refuses "draft refuses a tag that already exists" "already exists" bash "$actions/sealed-release/draft.sh"

# --- deploy (environment npm; contents: read, id-token: write) -----------------------
dp="$actions/npm-trusted-publish"
export GITHUB_REF=refs/tags/v1.2.3 GITHUB_EVENT_NAME=workflow_dispatch ACTIONS_ID_TOKEN_REQUEST_URL=https://oidc.invalid
refuses "deploy refuses any event but workflow_dispatch" "only from workflow_dispatch" \
  env GITHUB_EVENT_NAME=push bash "$dp/preflight.sh"
refuses "deploy refuses a static npm token" "NODE_AUTH_TOKEN is set" env NODE_AUTH_TOKEN_SET=true bash "$dp/preflight.sh"
refuses "deploy refuses a ref other than the input tag" "Run at the release tag" \
  env GITHUB_REF=refs/heads/main bash "$dp/preflight.sh"
refuses "deploy refuses without OIDC" "No OIDC token" env -u ACTIONS_ID_TOKEN_REQUEST_URL bash "$dp/preflight.sh"
bash "$dp/preflight.sh" > /dev/null && ok "deploy preflight passes for a dispatch at the tag with OIDC"

export EXPECT_NAME=@o/example GITHUB_OUTPUT="$work/verify.out"
refuses "deploy refuses when the release and tag are not this run's commit" "targets" \
  env GITHUB_SHA=$other bash "$dp/verify.sh"
echo "$other" > "$STUB_STATE/tag"
refuses "deploy refuses a tag that moved off the release commit" "expected a lightweight tag at" bash "$dp/verify.sh"
echo "$sha" > "$STUB_STATE/tag"
refuses "deploy refuses a package other than the activated one" "activation names" \
  env EXPECT_NAME=@o/other bash "$dp/verify.sh"
refuses "deploy refuses a release signed by another workflow" "does not verify" \
  env IDENTITY="https://github.com/o/r/.github/workflows/evil.yml@refs/heads/main" bash "$dp/verify.sh"
cp "$STUB_STATE/assets/$tgz" "$work/good.tgz"
echo junk >> "$STUB_STATE/assets/$tgz"
refuses "deploy refuses a tarball that does not match SHA256SUMS" "checksum mismatch" bash "$dp/verify.sh"
cp "$work/good.tgz" "$STUB_STATE/assets/$tgz"
bash "$dp/verify.sh" > /dev/null
[[ "$(out package "$GITHUB_OUTPUT")@$(out version "$GITHUB_OUTPUT")" == "@o/example@1.2.3" ]] || die "verify: outputs"
ok "deploy: ref, tag, release, tag commit, signatures, provenance commit, version and name agree"

export PACKAGE=@o/example VERSION=1.2.3 TARBALL="$(out tarball "$GITHUB_OUTPUT")"
DRY_RUN=true bash "$dp/publish.sh" > /dev/null
[[ ! -f "$STUB_STATE/npm_published_tag" ]] || die "dry run published"
ok "dry run publishes nothing"
bash "$dp/publish.sh" > /dev/null
[[ "$(cat "$STUB_STATE/npm_published_tag")" == latest ]] || die "publish: dist-tag"
ok "deploy publishes the sealed bytes and checks registry integrity"
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
