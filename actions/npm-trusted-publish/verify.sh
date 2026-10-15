#!/usr/bin/env bash
# Downloads a published release and proves, before npm sees it, that the tarball is the one
# the release workflow built, checksummed and signed from this exact commit.
set -euo pipefail

fail() { echo "::error title=npm trusted publish::$1"; exit 1; }

issuer="https://token.actions.githubusercontent.com"
identity="${IDENTITY:-}"
[[ -n "$identity" ]] || identity="https://github.com/${GITHUB_REPOSITORY:?}/.github/workflows/release.yml@refs/heads/main"
version="${TAG#v}"

draft=$(gh release view "$TAG" --json isDraft --jq .isDraft)
[[ "$draft" == "false" ]] || fail "release $TAG is not published"

dir="${RUNNER_TEMP:?}/sealed-release"
rm -rf "$dir" && mkdir -p "$dir"
gh release download "$TAG" --dir "$dir"
cd "$dir"

shopt -s nullglob
tarballs=(*.tgz)
((${#tarballs[@]} == 1)) || fail "expected exactly one .tgz in $TAG, found ${#tarballs[@]}"
tgz="${tarballs[0]}"
for f in SHA256SUMS SHA256SUMS.sigstore.json "$tgz.sigstore.json" "$tgz.intoto.sigstore.json"; do
  [[ -f "$f" ]] || fail "release $TAG has no $f"
done

verify_blob() {
  cosign verify-blob --bundle "$2" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$1" >/dev/null
}

# 1. The checksum list is the one the release workflow signed.
verify_blob SHA256SUMS SHA256SUMS.sigstore.json || fail "SHA256SUMS signature does not verify for $identity"
# 2. The tarball is listed, and every listed file matches.
awk '{print $2}' SHA256SUMS | grep -qxF "$tgz" || fail "$tgz is not listed in SHA256SUMS"
sha256sum --strict -c SHA256SUMS || fail "checksum mismatch"
# 3. The tarball's own signature and provenance verify against the same identity.
verify_blob "$tgz" "$tgz.sigstore.json" || fail "$tgz signature does not verify for $identity"
cosign verify-blob-attestation --bundle "$tgz.intoto.sigstore.json" --type slsaprovenance1 \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$tgz" >/dev/null \
  || fail "$tgz provenance does not verify for $identity"
# 4. The verified provenance says it was built from the commit this run is publishing.
built_from=$(jq -r '.dsseEnvelope.payload' "$tgz.intoto.sigstore.json" | base64 -d \
  | jq -r '.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit // empty')
[[ "$built_from" == "${GITHUB_SHA:?}" ]] || fail "$tgz was built from '${built_from:-unknown}', not $GITHUB_SHA"
# 5. The tarball's manifest is the tagged version.
manifest=$(tar -xOzf "$tgz" package/package.json)
pkg_version=$(jq -r .version <<< "$manifest")
package=$(jq -r .name <<< "$manifest")
[[ "$pkg_version" == "$version" ]] || fail "$tgz is version $pkg_version, release is $TAG"

echo "verify: $package@$version $(sha256sum "$tgz" | cut -d' ' -f1) signed by $identity, built from $GITHUB_SHA"
{
  echo "package=$package"
  echo "version=$version"
  echo "tarball=$dir/$tgz"
} >> "${GITHUB_OUTPUT:?}"
