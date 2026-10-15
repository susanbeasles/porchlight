#!/usr/bin/env bash
# Installs cosign v3.1.3 for linux/amd64, verified against a pinned SHA-256 (fail closed).
# Replaces sigstore/cosign-installer: this account's Actions policy allows only actions owned
# by susanbeasles or created by GitHub. The digest matches workflow_depot's tool registry,
# which cross-checked it against upstream cosign_checksums.txt.
set -euo pipefail

version="v3.1.3"
sha256="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
url="https://github.com/sigstore/cosign/releases/download/${version}/cosign-linux-amd64"

[[ "${RUNNER_OS:-}" == "Linux" && "${RUNNER_ARCH:-}" == "X64" ]] \
  || { echo "::error title=install cosign::only linux/amd64 runners are supported"; exit 1; }

dir="${RUNNER_TEMP:?}/cosign-bin"
mkdir -p "$dir"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$dir/cosign" "$url"
echo "${sha256}  $dir/cosign" | sha256sum --check --strict - >/dev/null \
  || { rm -f "$dir/cosign"; echo "::error title=install cosign::digest mismatch for $url"; exit 1; }
chmod 0755 "$dir/cosign"
echo "$dir" >> "${GITHUB_PATH:?}"
"$dir/cosign" version >/dev/null
echo "cosign ${version} installed, sha256 ${sha256}"
